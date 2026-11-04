# macOS native process qualification harness for Crystal Process Development 0009, probe revision 12.
# Compile with Crystal 1.21.1+; this file uses only the bundled workspace shards.
# Every signal targets a process/group created by this executable. Never elevate.
require "json"
require "c/sys/event"
require "process-supervision"

{% unless flag?(:darwin) %}
  {% raise "macos_process_probe.cr must be compiled for macOS" %}
{% end %}

@[Link("proc")]
lib MacProbeProc
  struct BSDInfo
    flags : UInt32
    status : UInt32
    xstatus : UInt32
    pid : UInt32
    ppid : UInt32
    uid : UInt32
    gid : UInt32
    ruid : UInt32
    rgid : UInt32
    svuid : UInt32
    svgid : UInt32
    reserved : UInt32
    comm : StaticArray(UInt8, 16)
    name : StaticArray(UInt8, 32)
    nfiles : UInt32
    pgid : UInt32
    pjobc : UInt32
    tdev : UInt32
    tpgid : UInt32
    nice : Int32
    start_sec : UInt64
    start_usec : UInt64
  end
end

# Darwin LP64 kevent struct. Keep the constants and ABI independent of the
# shard's new process observer so the results can expose ABI mistakes.
lib MacProbePosix
  fun setpgid(pid : Int32, pgid : Int32) : Int32
end

# Additional Darwin-native declarations used only by the qualification probe.
lib MacProbePosix
  fun fork : Int32
  fun _exit(status : Int32) : NoReturn
  fun waitpid(pid : Int32, status : Int32*, options : Int32) : Int32
  fun getppid : Int32
  fun getpgid(pid : Int32) : Int32
  fun setsid : Int32
  fun getsid(pid : Int32) : Int32
  fun dup2(oldfd : Int32, newfd : Int32) : Int32
  fun dup(fd : Int32) : Int32
end

# ---------------------------------------------------------------------------
# Revision 13 thread helpers.
#
# In Crystal 1.21 every thread that runs Crystal code needs a
# Fiber::ExecutionContext. A bare `Thread.new` thread has none, so anything that
# reaches the event loop (IO.pipe, Process.new, ANY FileDescriptor read/write
# including File.read and puts, Channel, a contended ::Mutex) raises
# `NilAssertionError: Thread#execution_context cannot be nil` there.
#
#   Thread       bare OS thread. Only for cases whose point is "this library call
#                works from a native thread". Never do harness I/O in the block;
#                synchronize with Thread::Mutex / Atomic, never ::Mutex/Channel.
#   ProbeThread  dedicated OS thread that owns an Isolated execution context.
#                Any Crystal code is safe. Use for everything else.
# ---------------------------------------------------------------------------
class ProbeThread
  def initialize(name : String = "probe", &block : ->)
    @context = Fiber::ExecutionContext::Isolated.new(name, &block)
  end

  def join : Nil
    @context.wait
  end
end

# A fiber on the default execution context with ProbeThread's join semantics. Use it where file
# descriptors are counted: every ProbeThread owns an event loop whose descriptors are not released
# until the process exits (Linux: 3 per context, macOS: 1), which would show up as a leak.
class ProbeFiber
  def initialize(name : String = "probe", &block : ->)
    @done = Channel(Exception?).new(1)
    spawn(name: name) do
      error = nil.as(Exception?)
      begin
        block.call
      rescue ex
        error = ex
      end
      @done.send(error)
    end
  end

  def join : Nil
    if error = @done.receive
      raise error
    end
  end
end

# Fixed-size integer slots shared between threads. `Array(Atomic(Int32))` does
# not work: Atomic is a struct, so `slots[i].set(x)` mutates a copy of the slot.
class ProbeSlots
  def initialize(size : Int32)
    @mutex = Thread::Mutex.new
    @values = Array(Int32).new(size, 0)
  end

  def []=(index : Int32, value : Int32) : Int32
    @mutex.synchronize { @values[index] = value }
  end

  def to_a : Array(Int32)
    @mutex.synchronize { @values.dup }
  end
end

def probe_failure_text(ex : Exception) : String
  "#{ex.class.name}: #{ex.message} @ #{ex.backtrace?.try(&.first?) || "no-backtrace"}"
end

module NativeProbe
  @@failures = 0
  @@skipped = 0
  @@cases = 0

  private EV_ADD           =     0x0001_u16
  private EV_DELETE        =     0x0002_u16
  private EV_ENABLE        =     0x0004_u16
  private EV_DISABLE       =     0x0008_u16
  private EV_ONESHOT       =     0x0010_u16
  private EV_CLEAR         =     0x0020_u16
  private EV_RECEIPT       =     0x0040_u16
  private EV_ERROR         =     0x4000_u16
  private EV_EOF           =     0x8000_u16
  private EVFILT_PROC      =         -5_i16
  private NOTE_EXIT        = 0x80000000_u32
  private NOTE_FORK        = 0x40000000_u32
  private NOTE_EXEC        = 0x20000000_u32
  private NOTE_REAP        = 0x10000000_u32
  private NOTE_SIGNAL      = 0x08000000_u32
  private NOTE_EXITSTATUS  = 0x04000000_u32
  private NOTE_EXIT_DETAIL = 0x02000000_u32
  private NOTE_TRACK       = 0x00000001_u32
  private NOTE_TRACKERR    = 0x00000002_u32
  private NOTE_CHILD       = 0x00000004_u32
  private PROC_PIDTBSDINFO =          3_i32
  private F_GETFD          =              1
  private F_SETFD          =              2
  private FD_CLOEXEC       =              1

  def self.wait_until(timeout : Time::Span, interval : Time::Span = 10.milliseconds, & : -> Bool) : Bool
    deadline = Time.instant + timeout
    loop do
      return true if yield
      return false if Time.instant >= deadline
      sleep interval
    end
  end

  def self.kevent_wait(kq : Int32, timeout : Time::Span) : {Int32, LibC::Kevent, Int32}
    event = LibC::Kevent.new
    seconds = timeout.total_seconds.to_i64
    nanos = (timeout.total_nanoseconds - seconds * 1_000_000_000).to_i64
    ts = LibC::Timespec.new(tv_sec: seconds, tv_nsec: nanos)
    Errno.value = Errno::NONE
    rc = LibC.kevent(kq, Pointer(LibC::Kevent).null, 0, pointerof(event), 1, pointerof(ts))
    {rc, event, Errno.value.value}
  end

  def self.kevent_change(kq : Int32, pid : Int64, flags : UInt16, fflags : UInt32,
                         udata : UInt64 = 0_u64, receipt : Bool = false) : {Int32, LibC::Kevent, Int32}
    change = LibC::Kevent.new(
      ident: pid.to_u64, filter: EVFILT_PROC, flags: flags,
      fflags: fflags, data: 0_i64, udata: Pointer(Void).new(udata)
    )
    event = LibC::Kevent.new
    Errno.value = Errno::NONE
    if receipt
      rc = LibC.kevent(kq, pointerof(change), 1, pointerof(event), 1, Pointer(LibC::Timespec).null)
    else
      rc = LibC.kevent(kq, pointerof(change), 1, Pointer(LibC::Kevent).null, 0, Pointer(LibC::Timespec).null)
    end
    {rc, event, Errno.value.value}
  end

  def self.observe_proc_event(pid : Int64, fflags : UInt32, timeout : Time::Span,
                              flags : UInt16 = EV_ADD | EV_ONESHOT,
                              udata : UInt64 = 0_u64) : Hash(String, String)
    result = {} of String => String
    kq = LibC.kqueue
    if kq < 0
      return details(stage: "kqueue", errno: Errno.value.value)
    end

    want_receipt = (flags & EV_RECEIPT) != 0
    chg_rc, chg_event, chg_errno = kevent_change(kq, pid, flags, fflags, udata, receipt: want_receipt)
    result["chg_rc"] = chg_rc.to_s
    result["chg_errno"] = chg_errno.to_s
    if (flags & EV_RECEIPT) != 0 && chg_rc == 1
      result["receipt_flags_hex"] = chg_event.flags.to_s(16)
      result["receipt_data"] = chg_event.data.to_s
    end
    if chg_rc < 0
      LibC.close(kq)
      return result
    end

    rc, event, event_errno = kevent_wait(kq, timeout)
    result["event_rc"] = rc.to_s
    result["event_errno"] = event_errno.to_s
    if rc == 1
      result["event_ident"] = event.ident.to_s
      result["event_filter"] = event.filter.to_s
      result["event_flags_hex"] = event.flags.to_s(16)
      result["event_fflags_hex"] = event.fflags.to_s(16)
      result["event_data"] = event.data.to_s
      result["event_udata"] = event.udata.address.to_u64.to_s
      result["event_eof"] = ((event.flags & EV_EOF) != 0).to_s
      result["event_error"] = ((event.flags & EV_ERROR) != 0).to_s
    end
    LibC.close(kq)
    result
  end

  def self.wait_for_observation(pid : Int64, timeout : Time::Span, & : ProcessHandle::Observation -> Bool) : ProcessHandle::Observation
    last = ProcessHandle.observe(pid)
    wait_until(timeout) do
      last = ProcessHandle.observe(pid)
      yield last
    end
    last
  end

  def self.pid_present_by_signal?(pid : Int64) : Bool
    return true if LibC.kill(pid.to_i32, 0) == 0
    Errno.value == Errno::EPERM
  end

  def self.fd_count_observation : Int32
    Dir.children("/dev/fd").size
  rescue
    -1
  end

  # Stdlib Process.new opens /dev/null three times (stdio_to_fd) before it spawns.
  # If the spawn raises, those File objects are only closed by their finalizers,
  # so descriptor counts are not stable until the GC has run. Measure both.
  def self.gc_settle : Nil
    3.times do
      GC.collect
      sleep 5.milliseconds
    end
  end

  def self.workdir : String
    @@workdir ||= ENV["PROCESS_PROBE_WORKDIR"]? || File.join(Dir.current, "process-macos-probe-#{Process.pid}")
  end

  def self.details(**values) : Hash(String, String)
    result = {} of String => String
    values.each { |key, value| result[key.to_s] = value.to_s }
    result
  end

  def self.record(name : String, status : String, data : Hash(String, String), elapsed : Time::Span) : Nil
    @@cases += 1
    @@failures += 1 if status == "fail" || status == "error"
    @@skipped += 1 if status == "skip"
    json = JSON.build do |j|
      j.object do
        j.field "schema", 1
        j.field "platform", "macos"
        j.field "checkpoint", "0009"
        j.field "case", name
        j.field "status", status
        j.field "elapsed_ms", elapsed.total_milliseconds.round(3)
        j.field "timestamp", Time.utc.to_s
        j.field "details", data
      end
    end
    STDOUT.puts(json)
    STDOUT.flush
    STDERR.puts("#{status.upcase}: #{name}")
  end

  def self.test(name : String, &)
    start = Time.instant
    begin
      passed, data = yield
      record(name, passed ? "pass" : "fail", data, Time.instant - start)
    rescue ex
      record(name, "error", details(class: ex.class.name, error: ex.message || "", backtrace: ex.backtrace?.try(&.first(5).join(" | ")) || ""), Time.instant - start)
    end
  end

  def self.note(name : String, data : Hash(String, String)) : Nil
    record(name, "info", data, Time::Span.zero)
  end

  def self.skip(name : String, message : String) : Nil
    record(name, "skip", details(reason: message), Time::Span.zero)
  end

  def self.finish : NoReturn
    record("summary", @@failures == 0 ? "pass" : "fail", details(cases: @@cases, failures: @@failures, skips: @@skipped, result_dir: workdir), Time::Span.zero)
    exit(@@failures == 0 ? 0 : 1)
  end

  def self.self_exe : String
    Process.executable_path || raise "could not locate probe executable"
  end

  def self.child_sleep(milliseconds : Int32) : Process
    Process.new(self_exe, ["--child", "sleep", milliseconds.to_s])
  end

  def self.native_zombie_helper : String
    ENV["PROCESS_ZOMBIE_HELPER"]? || raise "PROCESS_ZOMBIE_HELPER is not set; run through run-macos.sh"
  end

  def self.spawn_native_zombie_holder(marker : String, exit_code : Int32, hold_ms : Int32 = 1400) : Process
    File.delete?(marker)
    Process.new(native_zombie_helper, [marker, exit_code.to_s, hold_ms.to_s])
  end

  def self.wait_for_file(path : String, timeout : Time::Span = 2.seconds) : Bool
    deadline = Time.instant + timeout
    until File.exists?(path)
      return false if Time.instant >= deadline
      sleep 20.milliseconds
    end
    true
  end

  def self.cleanup(child : Process, reaped : Bool = false) : Nil
    unless reaped
      begin
        child.terminate
      rescue
      end
      begin
        child.wait
      rescue
      end
    end
    begin
      child.close
    rescue
    end
  end

  # NOTE_EXIT=0x80000000, EVFILT_PROC=-5, EV_ADD=0x1, EV_ONESHOT=0x10.
  # Uses a fresh kqueue per test; never permits indefinite kevent blocking.
  def self.await_exit_event(pid : Int64, timeout : Time::Span) : Hash(String, String)
    event_details = {} of String => String
    kq = LibC.kqueue
    if kq < 0
      return details(stage: "kqueue", errno: Errno.value.value)
    end
    begin
      change = LibC::Kevent.new(
        ident: pid.to_u64, filter: -5_i16, flags: 0x11_u16,
        fflags: 0x80000000_u32, data: 0_i64, udata: Pointer(Void).null
      )
      Errno.value = Errno::NONE
      rc = LibC.kevent(kq, pointerof(change), 1, Pointer(LibC::Kevent).null, 0, Pointer(LibC::Timespec).null)
      event_details["chg_rc"] = rc.to_s
      event_details["chg_errno"] = Errno.value.value.to_s
      return event_details if rc < 0
      event = uninitialized LibC::Kevent
      seconds = timeout.total_seconds.to_i64
      nanos = (timeout.total_nanoseconds - seconds * 1_000_000_000).to_i64
      ts = LibC::Timespec.new(tv_sec: seconds, tv_nsec: nanos)
      Errno.value = Errno::NONE
      rc = LibC.kevent(kq, Pointer(LibC::Kevent).null, 0, pointerof(event), 1, pointerof(ts))
      event_details["event_rc"] = rc.to_s
      event_details["event_errno"] = Errno.value.value.to_s
      if rc == 1
        event_details["event_ident"] = event.ident.to_s
        event_details["event_filter"] = event.filter.to_s
        event_details["event_flags_hex"] = event.flags.to_s(16)
        event_details["event_fflags_hex"] = event.fflags.to_s(16)
        event_details["event_data"] = event.data.to_s
        event_details["note_exit"] = ((event.fflags & 0x80000000_u32) != 0).to_s
        event_details["event_error"] = ((event.flags & 0x4000_u16) != 0).to_s
      end
      event_details
    ensure
      LibC.close(kq)
    end
  end

  def self.raw_waitpid(pid : Int32, options : Int32 = 0) : {Int32, Int32, Int32}
    status = 0_i32
    Errno.value = Errno::NONE
    rc = MacProbePosix.waitpid(pid, pointerof(status), options)
    {rc, status, Errno.value.value}
  end

  def self.raw_exit_code(status : Int32) : Int32?
    return nil unless (status & 0x7f) == 0
    (status >> 8) & 0xff
  end

  def self.raw_signal(status : Int32) : Int32?
    signal = status & 0x7f
    signal == 0 || signal == 0x7f ? nil : signal
  end

  def self.wait_pid_dead(pid : Int64, timeout : Time::Span = 2.seconds) : Bool
    wait_until(timeout) { ProcessHandle.observe(pid).state.dead? }
  rescue
    false
  end

  def self.wait_file_value(path : String, timeout : Time::Span = 2.seconds) : String
    raise "marker not created: #{path}" unless wait_for_file(path, timeout)
    File.read(path).strip
  end

  def self.with_kqueue(&)
    kq = LibC.kqueue
    raise "kqueue failed: #{Errno.value}" if kq < 0
    begin
      yield kq
    ensure
      LibC.close(kq)
    end
  end

  def self.kevent_register(kq : Int32, pid : Int64, fflags : UInt32,
                           flags : UInt16 = EV_ADD | EV_ONESHOT,
                           udata : UInt64 = 0_u64, receipt : Bool = false) : {Int32, LibC::Kevent, Int32}
    kevent_change(kq, pid, flags, fflags, udata, receipt: receipt)
  end

  def self.kevent_next(kq : Int32, timeout : Time::Span = 2.seconds) : {Int32, LibC::Kevent, Int32}
    kevent_wait(kq, timeout)
  end

  def self.spawn_group_child(ms : Int32 = 3000, suffix : String = "group", ignore_term : Bool = false) : {Process, Int64, String}
    marker = File.join(workdir, "#{suffix}-#{Process.pid}-#{Random.rand(1_000_000)}.txt")
    args = ["--child", "group-sleep", ms.to_s, marker]
    args << "ignore-term" if ignore_term
    child = Process.new(self_exe, args)
    raise "group child not ready" unless wait_for_file(marker)
    fields = File.read(marker).split('|')
    pgid = fields[1].to_i64
    raise "unsafe process group #{pgid}" unless pgid == child.pid && pgid != Process.pgid
    {child, pgid, marker}
  end

  def self.decode_kevent(event : LibC::Kevent) : Hash(String, String)
    details(ident: event.ident, filter: event.filter, flags_hex: event.flags.to_s(16),
      fflags_hex: event.fflags.to_s(16), data: event.data,
      udata: event.udata.address.to_u64, eof: (event.flags & EV_EOF) != 0,
      error: (event.flags & EV_ERROR) != 0)
  end

  def self.child_mode : NoReturn
    case ARGV[1]?
    when "sleep"
      ms = ARGV[2]?.try(&.to_i?) || 500
      sleep({ms, 6000}.min.milliseconds)
      exit 0
    when "group-sleep"
      ms = ARGV[2]?.try(&.to_i?) || 3000
      marker = ARGV[3]? || raise "missing marker"
      rc = MacProbePosix.setpgid(0, 0)
      Signal::TERM.ignore if ARGV[4]? == "ignore-term"
      File.write(marker, "#{Process.pid}|#{Process.pgid}|#{rc}|#{Errno.value.value}")
      sleep({ms, 6000}.min.milliseconds)
      exit(rc == 0 ? 0 : 20)
    when "spawn-grandchild"
      marker = ARGV[2]? || raise "missing marker"
      grandchild = Process.new(self_exe, ["--child", "sleep", "1700"])
      File.write(marker, grandchild.pid.to_s)
      exit 0
    when "spawn-grandchild-and-exit"
      marker = ARGV[2]? || raise "missing marker"
      delay_ms = ARGV[3]?.try(&.to_i?) || 80
      # Process.new closes stdio by default; the grandchild must inherit our stdout (the pipe the parent
      # is reading) or EOF arrives the moment this process exits and the case tests nothing.
      grandchild = Process.new(self_exe, ["--child", "sleep", "1200"], output: Process::Redirect::Inherit)
      File.write(marker, grandchild.pid.to_s)
      sleep delay_ms.milliseconds
      exit 0
    when "self-term"
      ms = ARGV[2]?.try(&.to_i?) || 300
      sleep({ms, 3000}.min.milliseconds)
      LibC.kill(Process.pid, Signal::TERM.value)
      sleep 1.second
      exit 90
    when "group-tree"
      marker = ARGV[2]? || raise "missing marker"
      rc = MacProbePosix.setpgid(0, 0)
      exit 81 if rc != 0
      grandchild = Process.new(self_exe, ["--child", "sleep", "3800"])
      File.write(marker, "#{Process.pid}|#{Process.pgid}|#{grandchild.pid}")
      sleep 4200.milliseconds
      exit 0
    when "group-controller"
      marker = ARGV[2]? || raise "missing marker"
      child = Process.new(self_exe, ["--child", "group-sleep", "1800", marker + ".ready"])
      deadline = Time.instant + 2.seconds
      until File.exists?(marker + ".ready")
        exit 82 if Time.instant >= deadline
        sleep 10.milliseconds
      end
      File.write(marker, "#{child.pid}|#{Process.pid}")
      sleep 2800.milliseconds
      exit 0
    when "args"
      marker = ARGV[2]? || raise "missing marker"
      File.write(marker, {"args" => ARGV[3..], "cwd" => Dir.current, "probe_env" => ENV["PROCESS_PROBE_TOKEN"]?}.to_json)
      exit 0
    when "env-dump"
      marker = ARGV[2]? || raise "missing marker"
      keys = ARGV[3..]
      values = {} of String => String?
      keys.each { |key| values[key] = ENV[key]? }
      File.write(marker, values.to_json)
      exit 0
    when "exit-code"
      exit(ARGV[2]?.try(&.to_i?) || 0)
    when "delayed-exit-code"
      ms = ARGV[2]?.try(&.to_i?) || 180
      code = ARGV[3]?.try(&.to_i?) || 0
      sleep ms.milliseconds
      exit code
    when "self-signal"
      ms = ARGV[2]?.try(&.to_i?) || 100
      sig = ARGV[3]?.try(&.to_i?) || Signal::TERM.value
      # Crystal's runtime intentionally ignores SIGPIPE. Reset it only for the
      # explicit signal-termination matrix so this child actually exercises the
      # platform's default SIGPIPE disposition.
      Signal::PIPE.reset if sig == Signal::PIPE.value
      sleep ms.milliseconds
      LibC.kill(Process.pid, sig)
      sleep 1.second
      exit 93
    when "self-signal-runtime-default"
      ms = ARGV[2]?.try(&.to_i?) || 100
      sig = ARGV[3]?.try(&.to_i?) || Signal::PIPE.value
      sleep ms.milliseconds
      LibC.kill(Process.pid, sig)
      sleep 120.milliseconds
      exit 93
    when "ignore-signal"
      marker = ARGV[2]? || raise "missing marker"
      signal = Signal.new(ARGV[3]?.try(&.to_i?) || Signal::USR1.value)
      signal.ignore
      File.write(marker, Process.pid.to_s)
      sleep 1600.milliseconds
      exit 0
    when "fork-after"
      marker = ARGV[2]? || raise "missing marker"
      sleep 180.milliseconds
      pid = MacProbePosix.fork
      if pid == 0
        sleep 180.milliseconds
        MacProbePosix._exit(0)
      elsif pid > 0
        File.write(marker, pid.to_s)
        raw_waitpid(pid)
        sleep 250.milliseconds
        exit 0
      else
        exit 71
      end
    when "exec-after"
      marker = ARGV[2]? || raise "missing marker"
      File.write(marker, Process.pid.to_s)
      sleep 180.milliseconds
      Process.exec(self_exe, ["--child", "sleep", "350"])
    when "zombie-holder"
      marker = ARGV[2]? || raise "missing marker"
      pid = MacProbePosix.fork
      if pid == 0
        MacProbePosix._exit(ARGV[3]?.try(&.to_i?) || 23)
      elsif pid > 0
        File.write(marker, pid.to_s)
        sleep 1400.milliseconds
        raw_waitpid(pid)
        exit 0
      else
        exit 72
      end
    when "stop-self"
      marker = ARGV[2]? || raise "missing marker"
      File.write(marker, Process.pid.to_s)
      LibC.kill(Process.pid, Signal::STOP.value)
      sleep 300.milliseconds
      exit 0
    when "setsid-sleep"
      marker = ARGV[2]? || raise "missing marker"
      rc = MacProbePosix.setsid
      sid = MacProbePosix.getsid(0)
      File.write(marker, "#{Process.pid}|#{Process.pgid}|#{rc}|#{sid}|#{Errno.value.value}")
      sleep 1300.milliseconds
      exit(rc >= 0 ? 0 : 73)
    when "setpgid-escape"
      marker = ARGV[2]? || raise "missing marker"
      rc = MacProbePosix.setpgid(0, 0)
      File.write(marker, "#{Process.pid}|#{Process.pgid}|#{rc}|#{Errno.value.value}")
      sleep 1300.milliseconds
      exit(rc == 0 ? 0 : 74)
    when "group-with-escape"
      marker = ARGV[2]? || raise "missing marker"
      mode = ARGV[3]? || "setsid-sleep"
      rc = MacProbePosix.setpgid(0, 0)
      exit 75 if rc != 0
      child_marker = marker + ".escaped"
      escaped = Process.new(self_exe, ["--child", mode, child_marker])
      raise "escape child not ready" unless wait_for_file(child_marker)
      File.write(marker, "#{Process.pid}|#{Process.pgid}|#{escaped.pid}|#{File.read(child_marker).strip}")
      sleep 1800.milliseconds
      exit 0
    when "fd-check"
      marker = ARGV[2]? || raise "missing marker"
      fd = ARGV[3]?.try(&.to_i?) || 200
      Errno.value = Errno::NONE
      rc = LibC.fcntl(fd, F_GETFD)
      File.write(marker, "#{rc}|#{Errno.value.value}")
      exit 0
    when "join-group-sleep"
      target = ARGV[2]?.try(&.to_i?) || raise "missing pgid"
      marker = ARGV[3]? || raise "missing marker"
      ms = ARGV[4]?.try(&.to_i?) || 1800
      rc = MacProbePosix.setpgid(0, target)
      File.write(marker, "#{Process.pid}|#{Process.pgid}|#{rc}|#{Errno.value.value}")
      sleep ms.milliseconds
      exit(rc == 0 ? 0 : 76)
    when "kqueue-close-wait-helper"
      marker = ARGV[2]? || raise "missing marker"
      kq = LibC.kqueue
      exit 77 if kq < 0
      rc, _, errno = kevent_register(kq, Process.pid, NOTE_EXIT, EV_ADD)
      ready = Atomic(Bool).new(false)
      result = "unset"
      waiter = Thread.new do
        ready.set(true)
        event_rc, _, event_errno = kevent_next(kq, 5.seconds)
        result = "#{event_rc}|#{event_errno}"
      end
      wait_until(500.milliseconds) { ready.get }
      sleep 20.milliseconds
      LibC.close(kq)
      returned = wait_until(700.milliseconds) { result != "unset" }
      File.write(marker, {"register_rc" => rc, "register_errno" => errno,
                          "waiter_returned" => returned, "waiter_result" => result}.to_json)
      exit 0
    when "stdio"
      payload = STDIN.gets_to_end
      STDOUT << "OUT:" << payload
      STDERR << "ERR:" << payload
      exit 0
    else
      STDERR.puts "unknown child mode"
      exit 64
    end
  end

  # Expanded Darwin qualification. Read-only observation except controlled
  # process groups and children created by this executable. No elevated access.
  def self.run_expanded : Nil
    test("identity_generation_equality_and_pid_reuse_model") do
      pid = Process.pid.to_i64
      a = ProcessHandle::Identity.new(pid, 201_u64)
      b = ProcessHandle::Identity.new(pid, 201_u64)
      changed = ProcessHandle::Identity.new(pid, 202_u64)
      missing = ProcessHandle::Identity.new(pid, nil)
      other = ProcessHandle::Identity.new(pid + 1_i64, 201_u64)
      passed = a.same_process?(b) && a.same_pid?(missing) && a.same_pid?(changed) &&
               !a.same_process?(changed) && !a.same_process?(missing) &&
               !missing.same_process?(missing) && !a.same_pid?(other) && !a.same_process?(other)
      {passed, details(valid_generation: a.same_process?(b), unknown_generation: missing.generation_known?,
        token_change_rejected: !a.same_process?(changed), pid_difference_rejected: !a.same_pid?(other))}
    end

    test("pid_input_rejection_zero_negative_and_overflow") do
      rejected = [] of String
      [-1_i64, 0_i64, Int32::MAX.to_i64 + 1_i64].each do |pid|
        begin
          ProcessHandle.observe(pid)
        rescue ArgumentError
          rejected << "observe:#{pid}"
        end
        begin
          ProcessHandle.lookup(pid)
        rescue ArgumentError
          rejected << "lookup:#{pid}"
        end
      end
      {rejected.size == 6, details(rejected: rejected.join(","))}
    end

    test("observation_state_predicates_are_explicit") do
      pid = Process.pid.to_i64
      live = ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Live, nil)
      zombie = ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Zombie, nil)
      dead = ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Dead, nil)
      unknown = ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Unknown, nil)
      ok = live.live? && live.present? && !live.terminated? && zombie.present? &&
           !zombie.live? && zombie.terminated? && dead.terminated? && !dead.present? &&
           unknown.present? && !unknown.live? && !unknown.terminated?
      {ok, details(live_present: live.present?, zombie_terminated: zombie.terminated?,
        unknown_live: unknown.live?, unknown_terminated: unknown.terminated?)}
    end

    test("self_start_generation_stable_across_64_observations") do
      identity = ProcessHandle.lookup(Process.pid) || raise "self identity unavailable"
      mismatch = 0
      failures = 0
      64.times do
        snapshot = ProcessHandle.observe(Process.pid)
        mismatch += 1 unless snapshot.identity.try { |candidate| identity.same_process?(candidate) } == true
        failures += 1 unless snapshot.state.live?
      end
      {identity.generation_known? && mismatch == 0 && failures == 0,
       details(samples: 64, generation_mismatches: mismatch, nonlive_samples: failures)}
    end

    test("native_threads_can_observe_current_identity") do
      baseline = ProcessHandle.lookup(Process.pid) || raise "missing self identity"
      outcomes = Array(String).new(5, "not_started")
      workers = Array(Thread).new(5) do |i|
        Thread.new do
          begin
            matched = 0
            30.times do
              candidate = ProcessHandle.lookup(Process.pid)
              matched += 1 if candidate && baseline.same_process?(candidate)
            end
            outcomes[i] = matched.to_s
          rescue ex
            outcomes[i] = "error:#{ex.class.name}:#{ex.message}"
          end
        end
      end
      workers.each(&.join)
      {outcomes.all? { |s| s == "30" },
       details(observations_per_thread: 30, thread_count: 5, successes: outcomes.join(","),
         caveat: "threaded execution, not proof of simultaneous CPU overlap")}
    end

    test("child_identity_distinct_from_parent") do
      child = child_sleep(900)
      reaped = false
      begin
        mine = ProcessHandle.lookup(Process.pid) || raise "no parent identity"
        theirs = ProcessHandle.lookup(child.pid) || raise "no child identity"
        distinct = !mine.same_pid?(theirs) && !mine.same_process?(theirs) && theirs.generation_known?
        status = child.wait
        reaped = true
        {distinct && status.success?, details(parent_pid: mine.pid, child_pid: theirs.pid,
          generation_known: theirs.generation_known?, distinct: distinct)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("rapid_child_start_tokens_and_reap_transitions") do
      total = 8
      observed = 0
      reaped = 0
      total.times do
        child = child_sleep(150)
        collected = false
        begin
          identity = ProcessHandle.lookup(child.pid)
          observed += 1 if identity && identity.generation_known? && identity.pid == child.pid
          status = child.wait
          collected = true
          dead = ProcessHandle.observe(child.pid)
          reaped += 1 if status.success? && dead.state.dead?
        ensure
          cleanup(child, collected)
        end
      end
      {observed == total && reaped == total, details(children: total,
        observed_generation: observed, reaped_as_dead: reaped)}
    end

    test("posix_group_invalid_pgid_guard") do
      rejected = [] of String
      [0_i64, -1_i64, Int32::MAX.to_i64 + 1_i64].each do |pid|
        begin
          ProcessSupervision.process_group(pid)
        rescue ArgumentError
          rejected << pid.to_s
        end
      end
      {rejected.size == 3, details(rejected_pgids: rejected.join(","))}
    end

    test("process_group_capability_guarantees_are_weak") do
      # Controller construction is harmless; never signal a group that we do not own.
      group = ProcessSupervision.process_group(Process.pid)
      begin
        {group.mechanism == ProcessSupervision::Mechanism::ProcessGroup &&
          !group.kill_on_close? && group.soft_termination?,
         details(mechanism: group.mechanism, kill_on_close: group.kill_on_close?,
           soft_termination: group.soft_termination?)}
      ensure
        group.close
      end
    end

    test("group_wait_empty_rejects_negative_timeout") do
      marker = File.join(workdir, "mac-validate-group-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "group-sleep", "1700", marker])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        raise "group child not ready" unless wait_for_file(marker)
        pgid = File.read(marker).split('|')[1].to_i64
        raise "unsafe group" unless pgid == child.pid && pgid != Process.pgid
        group = ProcessSupervision.process_group(pgid)
        negative = false
        begin
          group.wait_empty(-1.millisecond)
        rescue ArgumentError
          negative = true
        end
        immediate = group.wait_empty(0.milliseconds)
        timed = group.wait_empty(30.milliseconds)
        child.terminate
        status = child.wait
        reaped = true
        drained = group.wait_empty(2.seconds)
        {negative && !immediate && !timed && drained && status.signal_exit?,
         details(negative_rejected: negative, immediate: immediate,
           short_wait: timed, drained: drained, signal: status.exit_signal?)}
      ensure
        group.try &.close
        cleanup(child, reaped)
      end
    end

    test("group_close_idempotent_and_effect_admission") do
      group = ProcessSupervision.process_group(Process.pid)
      group.close
      group.close
      rejected = [] of String
      begin
        group.empty?
      rescue ProcessSupervision::Error::Closed
        rejected << "empty"
      end
      begin
        group.wait_empty(0.milliseconds)
      rescue ProcessSupervision::Error::Closed
        rejected << "wait_empty"
      end
      # The group PID happens to be our own pid, but the controller has been
      # closed before either effect is attempted; no signal can be admitted.
      begin
        group.terminate
      rescue ProcessSupervision::Error::Closed
        rejected << "terminate"
      end
      begin
        group.kill
      rescue ProcessSupervision::Error::Closed
        rejected << "kill"
      end
      {group.closed? && rejected.size == 4, details(rejected: rejected.join(","))}
    end

    test("group_empty_shutdown_fast_path") do
      # Use a group that was actually created by this test, not a random PID
      # treated as a group identifier after its process has exited.
      marker = File.join(workdir, "mac-empty-shutdown-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "group-sleep", "160", marker])
      reaped = false
      begin
        raise "isolated group not ready" unless wait_for_file(marker)
        pgid = File.read(marker).split('|')[1].to_i64
        raise "unsafe group" unless pgid == child.pid && pgid != Process.pgid
        status = child.wait
        reaped = true
        group = ProcessSupervision.process_group(pgid)
        begin
          was_empty = group.empty?
          report = group.shutdown(grace: 0.milliseconds, kill_after: 0.milliseconds, close: true)
          {status.success? && was_empty && report.drained? && report.closed? &&
            !report.kill_requested? && !report.terminate_requested?,
           details(was_empty: was_empty, drained: report.drained?, closed: report.closed?,
             terminate_requested: report.terminate_requested?, kill_requested: report.kill_requested?)}
        ensure
          group.close
        end
      ensure
        cleanup(child, reaped)
      end
    end

    test("group_shutdown_soft_tier_preserves_open_owner") do
      marker = File.join(workdir, "mac-soft-shutdown-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "group-sleep", "2200", marker])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        raise "group child not ready" unless wait_for_file(marker)
        pgid = File.read(marker).split('|')[1].to_i64
        raise "unsafe group" unless pgid == child.pid && pgid != Process.pgid
        group = ProcessSupervision.process_group(pgid)
        report = group.shutdown(grace: 800.milliseconds, kill_after: 1.second, close: false)
        status = child.wait
        reaped = true
        was_open = !group.closed?
        group.close
        {report.terminate_requested? && report.drained? && !report.kill_requested? &&
          !report.closed? && was_open && status.exit_signal? == Signal::TERM,
         details(terminated: report.terminate_requested?, kill_requested: report.kill_requested?,
           drained: report.drained?, controller_remained_open: was_open,
           signal: status.exit_signal?)}
      ensure
        group.try &.close
        cleanup(child, reaped)
      end
    end

    test("group_shutdown_escalates_when_term_is_ignored") do
      marker = File.join(workdir, "mac-escalate-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "group-sleep", "3600", marker, "ignore-term"])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        raise "group child not ready" unless wait_for_file(marker)
        pgid = File.read(marker).split('|')[1].to_i64
        raise "unsafe group" unless pgid == child.pid && pgid != Process.pgid
        group = ProcessSupervision.process_group(pgid)
        report = group.shutdown(grace: 100.milliseconds, kill_after: 2.seconds, close: false)
        status = child.wait
        reaped = true
        {report.terminate_requested? && report.kill_requested? && report.drained? && status.exit_signal? == Signal::KILL,
         details(terminate_requested: report.terminate_requested?, kill_requested: report.kill_requested?,
           drained: report.drained?, exit_signal: status.exit_signal?)}
      ensure
        group.try &.close
        cleanup(child, reaped)
      end
    end

    test("group_shutdown_negative_policy_rejected_without_closing_when_disabled") do
      group = ProcessSupervision.process_group(Process.pid)
      begin
        rejected = [] of String
        begin
          group.shutdown(grace: -1.millisecond, close: false)
        rescue ArgumentError
          rejected << "grace"
        end
        begin
          group.shutdown(kill_after: -1.millisecond, close: false)
        rescue ArgumentError
          rejected << "kill_after"
        end
        {rejected.size == 2 && !group.closed?,
         details(rejected: rejected.join(","), still_open: !group.closed?)}
      ensure
        group.close
      end
    end

    test("kqueue_live_process_timeout_without_exit_notification") do
      child = child_sleep(1400)
      reaped = false
      begin
        info = await_exit_event(child.pid, 40.milliseconds)
        after = ProcessHandle.observe(child.pid)
        status = child.wait
        reaped = true
        {info["chg_rc"]? == "0" && info["event_rc"]? == "0" &&
          after.state.live? && status.success?,
         info.merge(details(live_after_timeout: after.state, reaped: status.success?))}
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_current_process_does_not_signal_exit") do
      info = await_exit_event(Process.pid, 35.milliseconds)
      {info["chg_rc"]? == "0" && info["event_rc"]? == "0",
       info.merge(details(pid: Process.pid, self_exited: false))}
    end

    test("kqueue_invalid_pid_registration_error") do
      info = await_exit_event(Int32::MAX.to_i64, 20.milliseconds)
      {info["chg_rc"]? == "-1", info.merge(details(pid: Int32::MAX,
        classification: "invalid PID registration should fail; errno captured"))}
    end

    test("kqueue_child_signal_exit_notification") do
      # The child sends TERM to itself after a short delay. This avoids an
      # external thread trying to terminate the child while kevent blocks.
      child = Process.new(self_exe, ["--child", "self-term", "450"])
      reaped = false
      begin
        info = await_exit_event(child.pid, 2.seconds)
        status = child.wait
        reaped = true
        {info["chg_rc"]? == "0" && info["event_rc"]? == "1" &&
          info["note_exit"]? == "true" && status.exit_signal? == Signal::TERM,
         info.merge(details(signal_exit: status.signal_exit?, signal: status.exit_signal?))}
      ensure
        cleanup(child, reaped)
      end
    end

    test("process_group_direct_child_and_grandchild_receive_term") do
      marker = File.join(workdir, "mac-group-tree-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "group-tree", marker])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        raise "grandchild marker missing" unless wait_for_file(marker)
        parts = File.read(marker).split('|')
        pgid = parts[1].to_i64
        grandchild_pid = parts[2].to_i64
        raise "unsafe group" unless pgid == child.pid && pgid != Process.pgid
        group = ProcessSupervision.process_group(pgid)
        # The grandchild may briefly be in SIDL while starting. Wait for a
        # classified live state instead of relying on a scheduling delay.
        ready_deadline = Time.instant + 500.milliseconds
        before = ProcessHandle.observe(grandchild_pid)
        until before.state.live? || Time.instant >= ready_deadline
          sleep 10.milliseconds
          before = ProcessHandle.observe(grandchild_pid)
        end
        group.terminate
        direct = child.wait
        reaped = true
        deadline = Time.instant + 2.seconds
        final = ProcessHandle.observe(grandchild_pid)
        until final.terminated? || Time.instant >= deadline
          sleep 20.milliseconds
          final = ProcessHandle.observe(grandchild_pid)
        end
        {before.state.live? && direct.exit_signal? == Signal::TERM && final.terminated?,
         details(grandchild: grandchild_pid, before: before.state, after: final.state,
           direct_signal: direct.exit_signal?, interpretation: "nonchild observation; does not grant waitpid ownership")}
      ensure
        group.try &.close
        cleanup(child, reaped)
      end
    end

    test("process_group_controller_abrupt_death_does_not_kill_descendant") do
      marker = File.join(workdir, "mac-controller-death-#{Process.pid}.txt")
      owner = Process.new(self_exe, ["--child", "group-controller", marker])
      reaped = false
      begin
        raise "group controller marker missing" unless wait_for_file(marker)
        child_pid = File.read(marker).split('|')[0].to_i64
        before = ProcessHandle.observe(child_pid)
        owner.terminate
        status = owner.wait
        reaped = true
        sleep 70.milliseconds
        after = ProcessHandle.observe(child_pid)
        # The remaining process self-exits shortly; no PID-based cleanup
        # signal is issued to this now-unowned process.
        {before.state.live? && after.state.live? && status.signal_exit?,
         details(child_pid: child_pid, before_owner_death: before.state,
           after_owner_death: after.state, controller_signal: status.exit_signal?,
           interpretation: "POSIX process groups do not have kill-on-owner-death")}
      ensure
        cleanup(owner, reaped)
      end
    end

    test("isolated_spawn_preserves_unicode_argv_env_and_cwd") do
      marker = File.join(workdir, "mac-unicode-#{Process.pid}.json")
      args = ["", "alpha beta", "snowman-☃", "a\"b", "space  ", "slash\\value"]
      child = Process.new(self_exe, ["--child", "args", marker] + args,
        env: {"PROCESS_PROBE_TOKEN" => "mac-unicode-☃"}, chdir: workdir)
      reaped = false
      begin
        status = child.wait
        reaped = true
        payload = JSON.parse(File.read(marker))
        actual = payload["args"].as_a.map(&.as_s)
        exact_cwd = Path[payload["cwd"].as_s].expand == Path[workdir].expand
        {status.success? && actual == args && exact_cwd && payload["probe_env"].as_s == "mac-unicode-☃",
         details(args_exact: actual == args, cwd_exact: exact_cwd,
           env_exact: payload["probe_env"].as_s == "mac-unicode-☃")}
      ensure
        cleanup(child, reaped)
      end
    end
  end

  def self.run_spawn_exhaustive : Nil
    test("spawn_exit_code_0") do
      child = Process.new(self_exe, ["--child", "exit-code", "0"])
      status = child.wait; child.close
      {status.normal_exit? && status.exit_code? == 0, details(exit_code: status.exit_code?, raw: status.system_exit_status)}
    end

    test("spawn_exit_code_1") do
      child = Process.new(self_exe, ["--child", "exit-code", "1"])
      status = child.wait; child.close
      {status.normal_exit? && status.exit_code? == 1, details(exit_code: status.exit_code?, raw: status.system_exit_status)}
    end

    test("spawn_exit_code_42") do
      child = Process.new(self_exe, ["--child", "exit-code", "42"])
      status = child.wait; child.close
      {status.normal_exit? && status.exit_code? == 42, details(exit_code: status.exit_code?, raw: status.system_exit_status)}
    end

    test("spawn_exit_code_127") do
      child = Process.new(self_exe, ["--child", "exit-code", "127"])
      status = child.wait; child.close
      {status.normal_exit? && status.exit_code? == 127, details(exit_code: status.exit_code?, raw: status.system_exit_status)}
    end

    test("spawn_exit_code_255") do
      child = Process.new(self_exe, ["--child", "exit-code", "255"])
      status = child.wait; child.close
      {status.normal_exit? && status.exit_code? == 255, details(exit_code: status.exit_code?, raw: status.system_exit_status)}
    end

    test("spawn_signal_term_status") do
      child = Process.new(self_exe, ["--child", "self-signal", "80", Signal::TERM.value.to_s])
      status = child.wait; child.close
      {status.signal_exit? && status.exit_signal? == Signal::TERM && status.exit_code?.nil?,
       details(signal: status.exit_signal?, reason: status.exit_reason, raw: status.system_exit_status)}
    end

    test("spawn_signal_kill_status") do
      child = child_sleep(1200)
      LibC.kill(child.pid.to_i32, Signal::KILL.value)
      status = child.wait; child.close
      {status.signal_exit? && status.exit_signal? == Signal::KILL && status.exit_code?.nil?,
       details(signal: status.exit_signal?, reason: status.exit_reason, raw: status.system_exit_status)}
    end

    test("spawn_argv_empty_argument") do
      marker = File.join(workdir, "argv-empty-#{Process.pid}.json")
      expected = [""]
      child = Process.new(self_exe, ["--child", "args", marker] + expected)
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))["args"].as_a.map(&.as_s)
      {status.success? && actual == expected, details(exact: actual == expected)}
    end

    test("spawn_argv_spaces_tabs_newlines") do
      marker = File.join(workdir, "argv-space-#{Process.pid}.json")
      expected = [" ", "a b c", "a\tb", "a\nb", "  leading", "trailing  "]
      child = Process.new(self_exe, ["--child", "args", marker] + expected)
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))["args"].as_a.map(&.as_s)
      {status.success? && actual == expected, details(exact: actual == expected, count: actual.size)}
    end

    test("spawn_argv_quotes_backslashes") do
      marker = File.join(workdir, "argv-quotes-#{Process.pid}.json")
      expected = ["\"", "'", "a\"b", "a\\b", "\\\\", "x\\\"y"]
      child = Process.new(self_exe, ["--child", "args", marker] + expected)
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))["args"].as_a.map(&.as_s)
      {status.success? && actual == expected, details(exact: actual == expected)}
    end

    test("spawn_argv_unicode_rtl_emoji") do
      marker = File.join(workdir, "argv-unicode-#{Process.pid}.json")
      expected = ["snowman-☃", "emoji-🧪", "العربية", "עברית", "e\u0301"]
      child = Process.new(self_exe, ["--child", "args", marker] + expected)
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))["args"].as_a.map(&.as_s)
      {status.success? && actual == expected, details(exact: actual == expected)}
    end

    test("spawn_argv_long_64k") do
      marker = File.join(workdir, "argv-long-#{Process.pid}.json")
      expected = "x" * 65_536
      child = Process.new(self_exe, ["--child", "args", marker, expected])
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))["args"].as_a[0].as_s
      {status.success? && actual == expected, details(length: actual.bytesize, exact: actual == expected)}
    end

    test("spawn_environment_inherits_parent") do
      key = "PROCESS_PROBE_PARENT_INHERIT"
      old = ENV[key]?
      ENV[key] = "parent-value"
      marker = File.join(workdir, "env-inherit-#{Process.pid}.json")
      begin
        child = Process.new(self_exe, ["--child", "env-dump", marker, key])
        status = child.wait; child.close
        value = JSON.parse(File.read(marker))[key].as_s?
        {status.success? && value == "parent-value", details(value: value)}
      ensure
        if old
          ENV[key] = old
        else
          ENV.delete(key)
        end
      end
    end

    test("spawn_environment_override") do
      key = "PROCESS_PROBE_OVERRIDE"
      ENV[key] = "parent"
      marker = File.join(workdir, "env-override-#{Process.pid}.json")
      begin
        child = Process.new(self_exe, ["--child", "env-dump", marker, key], env: {key => "child"})
        status = child.wait; child.close
        value = JSON.parse(File.read(marker))[key].as_s?
        {status.success? && value == "child", details(value: value)}
      ensure
        ENV.delete(key)
      end
    end

    test("spawn_environment_delete_inherited_key") do
      key = "PROCESS_PROBE_DELETE"
      ENV[key] = "parent"
      marker = File.join(workdir, "env-delete-#{Process.pid}.json")
      begin
        env = {key => nil} of String => String?
        child = Process.new(self_exe, ["--child", "env-dump", marker, key], env: env)
        status = child.wait; child.close
        value = JSON.parse(File.read(marker))[key].as_s?
        {status.success? && value.nil?, details(value_nil: value.nil?)}
      ensure
        ENV.delete(key)
      end
    end

    test("spawn_environment_empty_value_preserved") do
      key = "PROCESS_PROBE_EMPTY"
      marker = File.join(workdir, "env-empty-#{Process.pid}.json")
      child = Process.new(self_exe, ["--child", "env-dump", marker, key], env: {key => ""})
      status = child.wait; child.close
      value = JSON.parse(File.read(marker))[key].as_s?
      {status.success? && value == "", details(value: value.inspect)}
    end

    test("spawn_clear_environment_removes_parent_and_keeps_explicit") do
      parent_key = "PROCESS_PROBE_CLEAR_PARENT"
      explicit_key = "PROCESS_PROBE_CLEAR_EXPLICIT"
      ENV[parent_key] = "parent"
      marker = File.join(workdir, "env-clear-#{Process.pid}.json")
      begin
        child = Process.new(self_exe, ["--child", "env-dump", marker, parent_key, explicit_key],
          env: {explicit_key => "explicit"}, clear_env: true)
        status = child.wait; child.close
        payload = JSON.parse(File.read(marker))
        parent = payload[parent_key].as_s?
        explicit = payload[explicit_key].as_s?
        {status.success? && parent.nil? && explicit == "explicit", details(parent_nil: parent.nil?, explicit: explicit)}
      ensure
        ENV.delete(parent_key)
      end
    end

    test("spawn_environment_unicode_value") do
      key = "PROCESS_PROBE_UNICODE"
      value = "☃🧪-العربية-עברית"
      marker = File.join(workdir, "env-unicode-#{Process.pid}.json")
      child = Process.new(self_exe, ["--child", "env-dump", marker, key], env: {key => value})
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))[key].as_s?
      {status.success? && actual == value, details(exact: actual == value)}
    end

    test("spawn_environment_long_64k") do
      key = "PROCESS_PROBE_LONG"
      value = "v" * 65_536
      marker = File.join(workdir, "env-long-#{Process.pid}.json")
      child = Process.new(self_exe, ["--child", "env-dump", marker, key], env: {key => value})
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))[key].as_s?
      {status.success? && actual == value, details(length: actual.try(&.bytesize), exact: actual == value)}
    end

    test("spawn_invalid_env_empty_key_rejected") do
      rejected = false; klass = ""
      begin
        Process.new(self_exe, ["--child", "sleep", "10"], env: {"" => "x"})
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_invalid_env_equals_key_rejected") do
      rejected = false; klass = ""
      begin
        Process.new(self_exe, ["--child", "sleep", "10"], env: {"A=B" => "x"})
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_invalid_env_key_nul_rejected") do
      rejected = false; klass = ""
      begin
        Process.new(self_exe, ["--child", "sleep", "10"], env: {"A\0B" => "x"})
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_invalid_env_value_nul_rejected") do
      rejected = false; klass = ""
      begin
        Process.new(self_exe, ["--child", "sleep", "10"], env: {"A" => "x\0y"})
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_argument_nul_rejected") do
      rejected = false; klass = ""
      begin
        Process.new(self_exe, ["--child", "args", "x", "a\0b"])
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_empty_command_vector_rejected") do
      rejected = false; klass = ""
      begin
        Process.new([] of String)
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_missing_executable_rejected") do
      rejected = false; klass = ""
      begin
        Process.new(File.join(workdir, "definitely-missing-executable"), [] of String)
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_non_executable_file_rejected") do
      path = File.join(workdir, "not-executable.txt")
      File.write(path, "plain text")
      File.chmod(path, 0o600)
      rejected = false; klass = ""
      begin
        Process.new(path, [] of String)
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_missing_cwd_rejected") do
      rejected = false; klass = ""
      begin
        Process.new(self_exe, ["--child", "sleep", "10"], chdir: File.join(workdir, "missing-dir"))
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_file_as_cwd_rejected") do
      file = File.join(workdir, "cwd-file.txt")
      File.write(file, "x")
      rejected = false; klass = ""
      begin
        Process.new(self_exe, ["--child", "sleep", "10"], chdir: file)
      rescue ex
        rejected = true; klass = ex.class.name
      end
      {rejected, details(rejected: rejected, class: klass)}
    end

    test("spawn_unicode_cwd_exact") do
      dir = File.join(workdir, "cwd-☃-🧪")
      Dir.mkdir_p(dir)
      marker = File.join(workdir, "unicode-cwd-#{Process.pid}.json")
      child = Process.new(self_exe, ["--child", "args", marker], chdir: dir)
      status = child.wait; child.close
      actual = JSON.parse(File.read(marker))["cwd"].as_s
      {status.success? && Path[actual].expand == Path[dir].expand,
       details(actual: actual, expected: dir)}
    end

    test("spawn_unicode_executable_copy_runs") do
      copy = File.join(workdir, "probe-☃-🧪")
      File.copy(self_exe, copy)
      File.chmod(copy, 0o755)
      child = Process.new(copy, ["--child", "exit-code", "23"])
      status = child.wait; child.close
      {status.exit_code? == 23, details(exit_code: status.exit_code?, path: copy)}
    end

    test("spawn_stdio_pipe_roundtrip") do
      child = Process.new(self_exe, ["--child", "stdio"],
        input: Process::Redirect::Pipe, output: Process::Redirect::Pipe, error: Process::Redirect::Pipe)
      payload = "hello-☃\nsecond-line\n"
      child.input << payload
      child.input.close
      stdout = child.output.gets_to_end
      stderr = child.error.gets_to_end
      status = child.wait
      child.close
      {status.success? && stdout == "OUT:#{payload}" && stderr == "ERR:#{payload}",
       details(stdout_exact: stdout == "OUT:#{payload}", stderr_exact: stderr == "ERR:#{payload}")}
    end

    test("spawn_fd_without_cloexec_is_inherited") do
      file = File.open(File::NULL, "r")
      target = 200
      begin
        raise "dup2 failed" if MacProbePosix.dup2(file.fd, target) < 0
        raise "clear cloexec failed" if LibC.fcntl(target, F_SETFD, 0) < 0
        marker = File.join(workdir, "fd-inherit-#{Process.pid}.txt")
        child = Process.new(self_exe, ["--child", "fd-check", marker, target.to_s])
        status = child.wait; child.close
        fields = File.read(marker).split('|')
        {status.success? && fields[0].to_i >= 0, details(child_fcntl_rc: fields[0], errno: fields[1])}
      ensure
        LibC.close(target)
        file.close
      end
    end

    test("spawn_fd_with_cloexec_is_not_inherited") do
      file = File.open(File::NULL, "r")
      target = 201
      begin
        raise "dup2 failed" if MacProbePosix.dup2(file.fd, target) < 0
        raise "set cloexec failed" if LibC.fcntl(target, F_SETFD, FD_CLOEXEC) < 0
        marker = File.join(workdir, "fd-cloexec-#{Process.pid}.txt")
        child = Process.new(self_exe, ["--child", "fd-check", marker, target.to_s])
        status = child.wait; child.close
        fields = File.read(marker).split('|')
        {status.success? && fields[0].to_i < 0, details(child_fcntl_rc: fields[0], errno: fields[1])}
      ensure
        LibC.close(target)
        file.close
      end
    end

    test("spawn_32_concurrent_children_complete") do
      children = Array(Process).new(32) { |i| Process.new(self_exe, ["--child", "delayed-exit-code", (20 + (i % 5) * 10).to_s, (i % 8).to_s]) }
      statuses = children.map(&.wait)
      children.each(&.close)
      expected = (0...32).map { |i| i % 8 }
      actual = statuses.map(&.exit_code?)
      {actual == expected, details(count: statuses.size, exact: actual == expected)}
    end

    test("spawn_failure_churn_does_not_leak_fds") do
      gc_settle
      before = fd_count_observation
      100.times do |i|
        begin
          Process.new(File.join(workdir, "missing-#{i}"), [] of String)
        rescue
        end
      end
      after_no_gc = fd_count_observation
      gc_settle
      after = fd_count_observation
      delta = before >= 0 && after >= 0 ? after - before : 0
      lingering = before >= 0 && after_no_gc >= 0 ? after_no_gc - before : 0
      {before < 0 || after < 0 || delta.abs <= 2,
       details(before: before, after: after, delta: delta, attempts: 100, after_no_gc: after_no_gc, lingering_until_gc: lingering)}
    end
  end

  def self.run_group_exhaustive : Nil
    test("group_kill_direct_child_and_drain") do
      child, pgid, _ = spawn_group_child(2200, "kill-direct")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        group.kill
        status = child.wait
        reaped = true
        drained = group.wait_empty(1.second)
        {status.exit_signal? == Signal::KILL && drained,
         details(signal: status.exit_signal?, drained: drained)}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_shutdown_soft_close_true") do
      child, pgid, _ = spawn_group_child(2200, "shutdown-soft-close")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        report = group.shutdown(grace: 1.second, kill_after: 500.milliseconds, close: true)
        status = child.wait
        reaped = true
        {report.terminate_requested? && !report.kill_requested? && report.drained? && report.closed? &&
          group.closed? && status.exit_signal? == Signal::TERM,
         details(terminate: report.terminate_requested?, kill: report.kill_requested?, drained: report.drained?, closed: report.closed?)}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_shutdown_escalated_close_true") do
      child, pgid, _ = spawn_group_child(3500, "shutdown-escalate-close", ignore_term: true)
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        report = group.shutdown(grace: 80.milliseconds, kill_after: 1.second, close: true)
        status = child.wait
        reaped = true
        {report.escalated? && report.drained? && report.closed? && status.exit_signal? == Signal::KILL,
         details(escalated: report.escalated?, drained: report.drained?, signal: status.exit_signal?)}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_empty_open_terminate_is_noop") do
      child, pgid, _ = spawn_group_child(70, "empty-term")
      reaped = false
      begin
        status = child.wait
        reaped = true
        group = ProcessSupervision.process_group(pgid)
        begin
          before = group.empty?
          group.terminate
          after = group.empty?
          {status.success? && before && after, details(before: before, after: after)}
        ensure
          group.close
        end
      ensure
        cleanup(child, reaped)
      end
    end

    test("group_empty_open_kill_is_noop") do
      child, pgid, _ = spawn_group_child(70, "empty-kill")
      reaped = false
      begin
        status = child.wait
        reaped = true
        group = ProcessSupervision.process_group(pgid)
        begin
          before = group.empty?
          group.kill
          after = group.empty?
          {status.success? && before && after, details(before: before, after: after)}
        ensure
          group.close
        end
      ensure
        cleanup(child, reaped)
      end
    end

    test("group_wait_empty_nil_unblocks_after_terminate") do
      child, pgid, _ = spawn_group_child(2400, "wait-nil")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      result = Channel(String).new(1)
      begin
        spawn do
          begin
            result.send(group.wait_empty(nil).to_s)
          rescue ex
            result.send("error:#{ex.class.name}")
          end
        end
        sleep 80.milliseconds
        group.terminate
        status = child.wait
        reaped = true
        observed = select
        when value = result.receive
          value
        when timeout(2.seconds)
          "timeout"
        end
        {status.exit_signal? == Signal::TERM && observed == "true", details(waiter: observed, signal: status.exit_signal?)}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_two_siblings_terminate_together") do
      leader, pgid, _ = spawn_group_child(3000, "siblings-term-leader")
      leader_reaped = false
      join_marker = File.join(workdir, "siblings-term-join-#{Process.pid}.txt")
      joiner = Process.new(self_exe, ["--child", "join-group-sleep", pgid.to_s, join_marker, "3000"])
      join_reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        raise "joiner not ready" unless wait_for_file(join_marker)
        group.terminate
        s1 = leader.wait; leader_reaped = true
        s2 = joiner.wait; join_reaped = true
        drained = group.wait_empty(1.second)
        {s1.exit_signal? == Signal::TERM && s2.exit_signal? == Signal::TERM && drained,
         details(leader_signal: s1.exit_signal?, joiner_signal: s2.exit_signal?, drained: drained)}
      ensure
        group.close
        cleanup(leader, leader_reaped)
        cleanup(joiner, join_reaped)
      end
    end

    test("group_two_siblings_kill_together") do
      leader, pgid, _ = spawn_group_child(3000, "siblings-kill-leader")
      leader_reaped = false
      join_marker = File.join(workdir, "siblings-kill-join-#{Process.pid}.txt")
      joiner = Process.new(self_exe, ["--child", "join-group-sleep", pgid.to_s, join_marker, "3000"])
      join_reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        raise "joiner not ready" unless wait_for_file(join_marker)
        group.kill
        s1 = leader.wait; leader_reaped = true
        s2 = joiner.wait; join_reaped = true
        drained = group.wait_empty(1.second)
        {s1.exit_signal? == Signal::KILL && s2.exit_signal? == Signal::KILL && drained,
         details(leader_signal: s1.exit_signal?, joiner_signal: s2.exit_signal?, drained: drained)}
      ensure
        group.close
        cleanup(leader, leader_reaped)
        cleanup(joiner, join_reaped)
      end
    end

    test("group_survives_leader_exit_while_member_remains") do
      leader, pgid, _ = spawn_group_child(180, "leader-exit")
      leader_reaped = false
      join_marker = File.join(workdir, "leader-exit-join-#{Process.pid}.txt")
      joiner = Process.new(self_exe, ["--child", "join-group-sleep", pgid.to_s, join_marker, "1800"])
      join_reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        raise "joiner not ready" unless wait_for_file(join_marker)
        leader_status = leader.wait; leader_reaped = true
        empty_after_leader = group.empty?
        group.terminate
        join_status = joiner.wait; join_reaped = true
        {leader_status.success? && !empty_after_leader && join_status.exit_signal? == Signal::TERM && group.wait_empty(1.second),
         details(empty_after_leader: empty_after_leader, join_signal: join_status.exit_signal?)}
      ensure
        group.close
        cleanup(leader, leader_reaped)
        cleanup(joiner, join_reaped)
      end
    end

    test("group_setsid_descendant_escapes_termination") do
      marker = File.join(workdir, "setsid-escape-#{Process.pid}.txt")
      leader = Process.new(self_exe, ["--child", "group-with-escape", marker, "setsid-sleep"])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        fields = wait_file_value(marker).split('|')
        pgid = fields[1].to_i64
        escaped_pid = fields[2].to_i64
        raise "unsafe group" unless pgid == leader.pid && pgid != Process.pgid
        group = ProcessSupervision.process_group(pgid)
        group.terminate
        status = leader.wait; reaped = true
        escaped_after = ProcessHandle.observe(escaped_pid)
        escaped_eventually_dead = wait_pid_dead(escaped_pid, 2.seconds)
        {status.exit_signal? == Signal::TERM && escaped_after.present? && !escaped_after.terminated? && escaped_eventually_dead,
         details(leader_signal: status.exit_signal?, escaped_state_after_group_term: escaped_after.state,
           escaped_eventually_dead: escaped_eventually_dead)}
      ensure
        group.try &.close
        cleanup(leader, reaped)
      end
    end

    test("group_setpgid_descendant_escapes_termination") do
      marker = File.join(workdir, "setpgid-escape-#{Process.pid}.txt")
      leader = Process.new(self_exe, ["--child", "group-with-escape", marker, "setpgid-escape"])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        fields = wait_file_value(marker).split('|')
        pgid = fields[1].to_i64
        escaped_pid = fields[2].to_i64
        group = ProcessSupervision.process_group(pgid)
        group.terminate
        status = leader.wait; reaped = true
        escaped_after = ProcessHandle.observe(escaped_pid)
        escaped_eventually_dead = wait_pid_dead(escaped_pid, 2.seconds)
        {status.exit_signal? == Signal::TERM && escaped_after.present? && !escaped_after.terminated? && escaped_eventually_dead,
         details(escaped_state_after_group_term: escaped_after.state, escaped_eventually_dead: escaped_eventually_dead)}
      ensure
        group.try &.close
        cleanup(leader, reaped)
      end
    end

    test("group_kill_does_not_reach_setsid_escape") do
      marker = File.join(workdir, "setsid-kill-escape-#{Process.pid}.txt")
      leader = Process.new(self_exe, ["--child", "group-with-escape", marker, "setsid-sleep"])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        fields = wait_file_value(marker).split('|')
        pgid = fields[1].to_i64
        escaped_pid = fields[2].to_i64
        group = ProcessSupervision.process_group(pgid)
        group.kill
        status = leader.wait; reaped = true
        escaped_after = ProcessHandle.observe(escaped_pid)
        eventual = wait_pid_dead(escaped_pid, 2.seconds)
        {status.exit_signal? == Signal::KILL && escaped_after.present? && !escaped_after.terminated? && eventual,
         details(escaped_state_after_group_kill: escaped_after.state, escaped_eventually_dead: eventual)}
      ensure
        group.try &.close
        cleanup(leader, reaped)
      end
    end

    test("group_stopped_member_can_be_terminated") do
      child, pgid, _ = spawn_group_child(2800, "stopped-term")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        LibC.kill(child.pid.to_i32, Signal::STOP.value)
        sleep 50.milliseconds
        stopped = ProcessHandle.observe(child.pid)
        group.terminate
        status = child.wait; reaped = true
        {stopped.state.live? && status.exit_signal? == Signal::TERM && group.wait_empty(1.second),
         details(stopped_state: stopped.state, exit_signal: status.exit_signal?)}
      ensure
        LibC.kill(child.pid.to_i32, Signal::CONT.value) rescue nil
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_stopped_member_can_be_killed") do
      child, pgid, _ = spawn_group_child(2800, "stopped-kill")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        LibC.kill(child.pid.to_i32, Signal::STOP.value)
        sleep 50.milliseconds
        stopped = ProcessHandle.observe(child.pid)
        group.kill
        status = child.wait; reaped = true
        {stopped.state.live? && status.exit_signal? == Signal::KILL && group.wait_empty(1.second),
         details(stopped_state: stopped.state, exit_signal: status.exit_signal?)}
      ensure
        LibC.kill(child.pid.to_i32, Signal::CONT.value) rescue nil
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_close_vs_terminate_native_thread_race") do
      child, pgid, _ = spawn_group_child(1800, "close-term-race")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      gate = Atomic(Bool).new(false)
      outcomes = Array(String).new(2, "unset")
      threads = [
        Thread.new do
          until gate.get
            Thread.yield
          end
          begin
            group.close
            outcomes[0] = "closed"
          rescue ex
            outcomes[0] = "error:#{ex.class.name}"
          end
        end,
        Thread.new do
          until gate.get
            Thread.yield
          end
          begin
            group.terminate
            outcomes[1] = "signaled"
          rescue ProcessSupervision::Error::Closed
            outcomes[1] = "closed"
          rescue ex
            outcomes[1] = "error:#{ex.class.name}"
          end
        end,
      ]
      begin
        gate.set(true)
        threads.each(&.join)
        child.terminate rescue nil
        child.wait; reaped = true
        allowed = outcomes[0] == "closed" && (outcomes[1] == "signaled" || outcomes[1] == "closed")
        {allowed, details(outcomes: outcomes.join(","))}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_close_vs_kill_native_thread_race") do
      child, pgid, _ = spawn_group_child(1800, "close-kill-race")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      gate = Atomic(Bool).new(false)
      outcomes = Array(String).new(2, "unset")
      threads = [
        Thread.new do
          until gate.get
            Thread.yield
          end
          begin
            group.close
            outcomes[0] = "closed"
          rescue ex
            outcomes[0] = "error:#{ex.class.name}"
          end
        end,
        Thread.new do
          until gate.get
            Thread.yield
          end
          begin
            group.kill
            outcomes[1] = "signaled"
          rescue ProcessSupervision::Error::Closed
            outcomes[1] = "closed"
          rescue ex
            outcomes[1] = "error:#{ex.class.name}"
          end
        end,
      ]
      begin
        gate.set(true)
        threads.each(&.join)
        child.terminate rescue nil
        child.wait; reaped = true
        allowed = outcomes[0] == "closed" && (outcomes[1] == "signaled" || outcomes[1] == "closed")
        {allowed, details(outcomes: outcomes.join(","))}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_wait_empty_vs_close_wakes_with_closed") do
      child, pgid, _ = spawn_group_child(1800, "wait-close-race")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      outcome = Channel(String).new(1)
      begin
        spawn do
          begin
            outcome.send("result:#{group.wait_empty(2.seconds)}")
          rescue ex : ProcessSupervision::Error::Closed
            outcome.send("closed")
          rescue ex
            outcome.send("error:#{ex.class.name}")
          end
        end
        sleep 60.milliseconds
        group.close
        observed = select
        when value = outcome.receive
          value
        when timeout(1.second)
          "timeout"
        end
        child.terminate
        child.wait; reaped = true
        {observed == "closed", details(waiter: observed)}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_shutdown_on_closed_owner_rejected") do
      group = ProcessSupervision.process_group(Process.pid)
      group.close
      outcome = "unexpected"
      begin
        group.shutdown(grace: 0.milliseconds, kill_after: 0.milliseconds, close: true)
      rescue ex : ProcessSupervision::Error::Closed
        outcome = "closed"
      end
      {outcome == "closed", details(outcome: outcome, still_closed: group.closed?)}
    end

    test("group_shutdown_invalid_grace_close_true_observation") do
      child, pgid, _ = spawn_group_child(700, "invalid-grace-close")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        rejected = false
        begin
          group.shutdown(grace: -1.millisecond, kill_after: 0.milliseconds, close: true)
        rescue ArgumentError
          rejected = true
        end
        closed = group.closed?
        child.terminate
        child.wait; reaped = true
        {rejected, details(rejected: rejected, closed_after_invalid_policy: closed,
          note: "records validation-vs-cleanup ordering; closed state is diagnostic")}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("group_controller_churn_100_cycles") do
      failures = 0
      100.times do |i|
        child, pgid, _ = spawn_group_child(12, "group-churn-#{i}")
        reaped = false
        begin
          group = ProcessSupervision.process_group(pgid)
          child.wait; reaped = true
          failures += 1 unless group.wait_empty(500.milliseconds)
          group.close
          failures += 1 unless group.closed?
        ensure
          cleanup(child, reaped)
        end
      end
      {failures == 0, details(cycles: 100, failures: failures)}
    end
  end

  def self.run_kqueue_exhaustive : Nil
    test("kqueue_exitstatus_zero_matches_wait_status") do
      child = Process.new(self_exe, ["--child", "delayed-exit-code", "160", "0"])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, reg_errno = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
          event_rc, event, event_errno = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXIT) != 0 &&
               (event.fflags & NOTE_EXITSTATUS) != 0 && event.data.to_u32 == status.system_exit_status
          {ok, decode_kevent(event).merge(details(reg_rc: reg_rc, reg_errno: reg_errno,
            event_errno: event_errno, status_raw: status.system_exit_status))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_exitstatus_nonzero_matches_wait_status") do
      child = Process.new(self_exe, ["--child", "delayed-exit-code", "160", "37"])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && status.exit_code? == 37 &&
               (event.fflags & NOTE_EXITSTATUS) != 0 && event.data.to_u32 == status.system_exit_status
          {ok, decode_kevent(event).merge(details(exit_code: status.exit_code?, status_raw: status.system_exit_status))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_exitstatus_sigterm_matches_wait_status") do
      child = Process.new(self_exe, ["--child", "self-signal", "160", Signal::TERM.value.to_s])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && status.exit_signal? == Signal::TERM &&
               event.data.to_u32 == status.system_exit_status
          {ok, decode_kevent(event).merge(details(signal: status.exit_signal?, status_raw: status.system_exit_status))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_exitstatus_sigkill_matches_wait_status") do
      child = child_sleep(1800)
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
          LibC.kill(child.pid.to_i32, Signal::KILL.value)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && status.exit_signal? == Signal::KILL &&
               event.data.to_u32 == status.system_exit_status
          {ok, decode_kevent(event).merge(details(signal: status.exit_signal?, status_raw: status.system_exit_status))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_exit_detail_request_preserves_exit_event") do
      child = Process.new(self_exe, ["--child", "self-signal", "160", Signal::KILL.value.to_s])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXIT_DETAIL)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXIT) != 0 && status.signal_exit?
          {ok, decode_kevent(event).merge(details(exit_detail_bits: (event.fflags & 0x00070000_u32).to_s(16)))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_note_fork_observed") do
      marker = File.join(workdir, "fork-event-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "fork-after", marker])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_FORK)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_FORK) != 0 && status.success?
          {ok, decode_kevent(event).merge(details(grandchild: File.exists?(marker) ? File.read(marker).strip : "missing"))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_note_exec_observed") do
      marker = File.join(workdir, "exec-event-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "exec-after", marker])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXEC)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXEC) != 0 && status.success?
          {ok, decode_kevent(event).merge(details(marker: File.exists?(marker)))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_note_signal_observed_even_when_ignored") do
      marker = File.join(workdir, "signal-event-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "ignore-signal", marker, Signal::USR1.value.to_s])
      reaped = false
      begin
        raise "signal child not ready" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL, EV_ADD)
          LibC.kill(child.pid.to_i32, Signal::USR1.value)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_SIGNAL) != 0 && status.success?
          {ok, decode_kevent(event).merge(details(signal_sent: Signal::USR1.value))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_signal_filter_rearms_with_ev_clear_semantics") do
      marker = File.join(workdir, "signal-rearm-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "ignore-signal", marker, Signal::USR1.value.to_s])
      reaped = false
      begin
        raise "signal child not ready" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL, EV_ADD)
          LibC.kill(child.pid.to_i32, Signal::USR1.value)
          first_rc, first, _ = kevent_next(kq)
          LibC.kill(child.pid.to_i32, Signal::USR1.value)
          second_rc, second, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && first_rc == 1 && second_rc == 1 &&
               (first.fflags & NOTE_SIGNAL) != 0 && (second.fflags & NOTE_SIGNAL) != 0 && status.success?
          {ok, details(first: decode_kevent(first).to_json, second: decode_kevent(second).to_json)}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_fork_then_exit_delivers_both_without_oneshot") do
      marker = File.join(workdir, "fork-exit-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "fork-after", marker])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_FORK | NOTE_EXIT, EV_ADD)
          seen = 0_u32
          events = [] of String
          2.times do
            rc, event, _ = kevent_next(kq, 2.seconds)
            if rc == 1
              seen |= event.fflags
              events << decode_kevent(event).to_json
            end
          end
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && (seen & NOTE_FORK) != 0 && (seen & NOTE_EXIT) != 0 && status.success?
          {ok, details(seen_hex: seen.to_s(16), events: events.join(" | "))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_signal_then_exit_delivers_both") do
      child = Process.new(self_exe, ["--child", "self-signal", "260", Signal::TERM.value.to_s])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL | NOTE_EXIT, EV_ADD)
          seen = 0_u32
          events = [] of String
          2.times do
            rc, event, _ = kevent_next(kq, 2.seconds)
            if rc == 1
              seen |= event.fflags
              events << decode_kevent(event).to_json
            end
          end
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && (seen & NOTE_SIGNAL) != 0 && (seen & NOTE_EXIT) != 0 && status.exit_signal? == Signal::TERM
          {ok, details(seen_hex: seen.to_s(16), events: events.join(" | "))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_ev_receipt_valid_registration_reports_zero_error") do
      result = with_kqueue do |kq|
        rc, receipt, errno = kevent_register(kq, Process.pid, NOTE_EXIT, EV_ADD | EV_RECEIPT,
          0x11223344_u64, receipt: true)
        ok = rc == 1 && (receipt.flags & EV_ERROR) != 0 && receipt.data == 0
        {ok, decode_kevent(receipt).merge(details(rc: rc, errno: errno))}
      end
      result
    end

    test("kqueue_ev_receipt_invalid_pid_reports_error") do
      result = with_kqueue do |kq|
        rc, receipt, errno = kevent_register(kq, Int32::MAX, NOTE_EXIT, EV_ADD | EV_RECEIPT,
          0_u64, receipt: true)
        ok = rc == 1 && (receipt.flags & EV_ERROR) != 0 && receipt.data != 0
        {ok, decode_kevent(receipt).merge(details(rc: rc, syscall_errno: errno, receipt_errno: receipt.data))}
      end
      result
    end

    test("kqueue_ev_delete_suppresses_future_signal_event") do
      marker = File.join(workdir, "delete-signal-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "ignore-signal", marker, Signal::USR1.value.to_s])
      reaped = false
      begin
        raise "child not ready" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          add_rc, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL, EV_ADD)
          del_rc, _, _ = kevent_change(kq, child.pid, EV_DELETE, 0_u32)
          LibC.kill(child.pid.to_i32, Signal::USR1.value)
          event_rc, _, event_errno = kevent_next(kq, 80.milliseconds)
          status = child.wait
          reaped = true
          {add_rc == 0 && del_rc == 0 && event_rc == 0 && status.success?,
           details(add_rc: add_rc, delete_rc: del_rc, event_rc: event_rc, event_errno: event_errno)}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_ev_disable_then_enable_delivers_pending_signal") do
      marker = File.join(workdir, "disable-enable-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "ignore-signal", marker, Signal::USR1.value.to_s])
      reaped = false
      begin
        raise "child not ready" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          add_rc, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL, EV_ADD | EV_DISABLE)
          LibC.kill(child.pid.to_i32, Signal::USR1.value)
          disabled_rc, _, _ = kevent_next(kq, 80.milliseconds)
          enable_rc, _, _ = kevent_change(kq, child.pid, EV_ENABLE, 0_u32)
          event_rc, event, _ = kevent_next(kq, 500.milliseconds)
          status = child.wait
          reaped = true
          ok = add_rc == 0 && disabled_rc == 0 && enable_rc == 0 && event_rc == 1 &&
               (event.fflags & NOTE_SIGNAL) != 0 && status.success?
          {ok, decode_kevent(event).merge(details(disabled_rc: disabled_rc, enable_rc: enable_rc))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_readd_modifies_filter_and_udata") do
      marker = File.join(workdir, "readd-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "ignore-signal", marker, Signal::USR1.value.to_s])
      reaped = false
      begin
        raise "child not ready" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          first_rc, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL, EV_ADD, 0x11_u64)
          second_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT, EV_ADD, 0x22_u64)
          LibC.kill(child.pid.to_i32, Signal::USR1.value)
          quiet_rc, _, _ = kevent_next(kq, 80.milliseconds)
          child.terminate
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          ok = first_rc == 0 && second_rc == 0 && quiet_rc == 0 && event_rc == 1 &&
               (event.fflags & NOTE_EXIT) != 0 && event.udata.address.to_u64 == 0x22_u64 && status.signal_exit?
          {ok, decode_kevent(event).merge(details(quiet_rc: quiet_rc))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_udata_roundtrip") do
      child = child_sleep(240)
      reaped = false
      begin
        result = with_kqueue do |kq|
          token = 0x1234abcd_u64
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT, EV_ADD | EV_ONESHOT, token)
          event_rc, event, _ = kevent_next(kq)
          status = child.wait
          reaped = true
          {reg_rc == 0 && event_rc == 1 && event.udata.address.to_u64 == token && status.success?,
           decode_kevent(event).merge(details(expected_udata: token))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_oneshot_not_redelivered") do
      child = child_sleep(200)
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT, EV_ADD | EV_ONESHOT)
          first_rc, first, _ = kevent_next(kq)
          second_rc, _, _ = kevent_next(kq, 50.milliseconds)
          status = child.wait
          reaped = true
          {reg_rc == 0 && first_rc == 1 && second_rc == 0 && (first.fflags & NOTE_EXIT) != 0 && status.success?,
           decode_kevent(first).merge(details(second_rc: second_rc))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_two_independent_queues_receive_same_exit") do
      child = child_sleep(260)
      reaped = false
      kq1 = LibC.kqueue
      kq2 = LibC.kqueue
      begin
        raise "kqueue failed" if kq1 < 0 || kq2 < 0
        r1, _, _ = kevent_register(kq1, child.pid, NOTE_EXIT)
        r2, _, _ = kevent_register(kq2, child.pid, NOTE_EXIT)
        e1_rc, e1, _ = kevent_next(kq1)
        e2_rc, e2, _ = kevent_next(kq2)
        status = child.wait
        reaped = true
        ok = r1 == 0 && r2 == 0 && e1_rc == 1 && e2_rc == 1 &&
             (e1.fflags & NOTE_EXIT) != 0 && (e2.fflags & NOTE_EXIT) != 0 && status.success?
        {ok, details(first: decode_kevent(e1).to_json, second: decode_kevent(e2).to_json)}
      ensure
        LibC.close(kq1) if kq1 >= 0
        LibC.close(kq2) if kq2 >= 0
        cleanup(child, reaped)
      end
    end

    test("kqueue_many_children_one_queue_all_exit_events") do
      children = [] of Process
      reaped = [] of Bool
      begin
        result = with_kqueue do |kq|
          # Register each child immediately after it starts. A registration made after the child has exited
          # fails with ESRCH (measured 200/200: explore/macos/kqueue_zombie.c), which spawning eight Crystal
          # children one after another can cause on a loaded runner. NOTE: that does not explain the one
          # observed failure (8 successful registrations, 7 events); `missing_pids`/`event_rcs` below record
          # more if it recurs.
          registrations = 0
          8.times do |i|
            child = Process.new(self_exe, ["--child", "delayed-exit-code", (180 + i * 25).to_s, i.to_s])
            children << child
            reaped << false
            rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT, EV_ADD | EV_ONESHOT)
            registrations += 1 if rc == 0
          end
          seen = Set(UInt64).new
          event_rcs = [] of Int32
          8.times do
            rc, event, _ = kevent_next(kq, 2.seconds)
            event_rcs << rc
            seen << event.ident if rc == 1 && (event.fflags & NOTE_EXIT) != 0
          end
          missing_pids = children.map(&.pid.to_u64).reject { |pid| seen.includes?(pid) }
          statuses = children.map_with_index do |child, i|
            status = child.wait
            reaped[i] = true
            status
          end
          {registrations == 8 && seen.size == 8 && statuses.all?(&.normal_exit?),
           details(registrations: registrations, unique_events: seen.size, exit_codes: statuses.map(&.exit_code?).join(","),
             event_rcs: event_rcs.join(","), missing_pids: missing_pids.join(","))}
        end
        result
      ensure
        children.each_with_index { |child, i| cleanup(child, reaped[i]) }
      end
    end

    test("kqueue_zero_timeout_live_process_returns_no_event") do
      child = child_sleep(650)
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT)
          event_rc, _, errno = kevent_next(kq, Time::Span.zero)
          child.terminate
          child.wait
          reaped = true
          {reg_rc == 0 && event_rc == 0, details(event_rc: event_rc, errno: errno)}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_reaped_pid_registration_is_esrch") do
      child = child_sleep(60)
      status = child.wait
      child.close
      result = with_kqueue do |kq|
        Errno.value = Errno::NONE
        rc, _, errno = kevent_register(kq, child.pid, NOTE_EXIT)
        {status.success? && rc < 0 && errno == Errno::ESRCH.value,
         details(rc: rc, errno: errno, expected: Errno::ESRCH.value)}
      end
      result
    end

    test("kqueue_registration_exit_race_has_only_exit_or_esrch") do
      unexpected = 0
      exit_events = 0
      esrch = 0
      30.times do
        child = Process.new(self_exe, ["--child", "delayed-exit-code", "5", "0"])
        reaped = false
        begin
          with_kqueue do |kq|
            rc, _, errno = kevent_register(kq, child.pid, NOTE_EXIT)
            if rc == 0
              event_rc, event, _ = kevent_next(kq, 500.milliseconds)
              if event_rc == 1 && (event.fflags & NOTE_EXIT) != 0
                exit_events += 1
              else
                unexpected += 1
              end
            elsif errno == Errno::ESRCH.value
              esrch += 1
            else
              unexpected += 1
            end
          end
          child.wait
          reaped = true
        ensure
          cleanup(child, reaped)
        end
      end
      {unexpected == 0 && exit_events + esrch == 30,
       details(iterations: 30, exit_events: exit_events, esrch: esrch, unexpected: unexpected)}
    end

    test("kqueue_close_before_exit_does_not_affect_child") do
      child = child_sleep(180)
      reaped = false
      begin
        kq = LibC.kqueue
        raise "kqueue failed" if kq < 0
        rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT)
        LibC.close(kq)
        status = child.wait
        reaped = true
        {rc == 0 && status.success?, details(registration_rc: rc, exit_code: status.exit_code?)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_deprecated_note_track_is_rejected_or_ignored_safely") do
      result = with_kqueue do |kq|
        rc, receipt, errno = kevent_register(kq, Process.pid, NOTE_TRACK | NOTE_CHILD,
          EV_ADD | EV_RECEIPT, 0_u64, receipt: true)
        safe = rc == 1 && (receipt.flags & EV_ERROR) != 0
        {safe, decode_kevent(receipt).merge(details(rc: rc, syscall_errno: errno,
          note: "XNU declares NOTE_TRACK/NOTE_CHILD unsupported since 10.5; receipt records native error"))}
      end
      result
    end

    test("kqueue_note_reap_deprecated_registration_race_classified") do
      marker = File.join(workdir, "note-reap-#{Process.pid}.txt")
      holder = spawn_native_zombie_holder(marker, 11)
      reaped = false
      begin
        zombie_pid = wait_file_value(marker).to_i64
        result = with_kqueue do |kq|
          reg_rc, _, reg_errno = kevent_register(kq, zombie_pid, NOTE_REAP, EV_ADD | EV_ONESHOT)
          if reg_rc == 0
            event_rc, event, event_errno = kevent_next(kq, 2.seconds)
            status = holder.wait
            reaped = true
            ok = event_rc == 1 && (event.fflags & NOTE_REAP) != 0 && status.success?
            {ok, decode_kevent(event).merge(details(registration: "accepted", reg_errno: reg_errno,
              event_errno: event_errno, note: "NOTE_REAP is deprecated; accepted registration must deliver the bounded reap event"))}
          else
            status = holder.wait
            reaped = true
            ok = reg_errno == Errno::ESRCH.value && status.success?
            {ok, details(registration: "esrch", reg_rc: reg_rc, reg_errno: reg_errno,
              note: "Darwin may reject registration after the child is already an unreaped zombie")}
          end
        end
        result
      ensure
        cleanup(holder, reaped)
      end
    end

    test("kqueue_nonchild_exitstatus_request_stays_observational") do
      marker = File.join(workdir, "nonchild-exitstatus-#{Process.pid}.txt")
      intermediate = Process.new(self_exe, ["--child", "spawn-grandchild", marker])
      reaped = false
      begin
        grandchild_pid = wait_file_value(marker).to_i64
        status = intermediate.wait
        reaped = true
        result = with_kqueue do |kq|
          reg_rc, _, reg_errno = kevent_register(kq, grandchild_pid, NOTE_EXIT | NOTE_EXITSTATUS)
          event_rc, event, event_errno = kevent_next(kq, 3.seconds)
          ok = status.success? && reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXIT) != 0
          {ok, decode_kevent(event).merge(details(reg_errno: reg_errno, event_errno: event_errno,
            exitstatus_flag_returned: (event.fflags & NOTE_EXITSTATUS) != 0,
            interpretation: "nonchild exit observation only; no wait-status authority inferred"))}
        end
        result
      ensure
        cleanup(intermediate, reaped)
      end
    end

    test("kqueue_registration_fd_churn_is_bounded") do
      before = fd_count_observation
      120.times do
        kq = LibC.kqueue
        raise "kqueue failed" if kq < 0
        rc, _, _ = kevent_register(kq, Process.pid, NOTE_EXIT)
        raise "registration failed" unless rc == 0
        LibC.close(kq)
      end
      after = fd_count_observation
      delta = before >= 0 && after >= 0 ? after - before : 0
      {before < 0 || after < 0 || delta.abs <= 2, details(before: before, after: after, delta: delta, cycles: 120)}
    end
  end

  def self.run_identity_exhaustive : Nil
    test("darwin_open_explicit_pid_is_unsupported") do
      result = "unexpected"
      begin
        handle = ProcessHandle.open(Process.pid)
        handle.close
      rescue ProcessHandle::Error::Unsupported
        result = "unsupported"
      end
      {result == "unsupported", details(result: result)}
    end

    test("self_lookup_generation_nonzero_and_repeatable") do
      a = ProcessHandle.lookup(Process.pid) || raise "missing identity"
      b = ProcessHandle.lookup(Process.pid) || raise "missing identity"
      generation = a.generation
      {generation != nil && generation != 0_u64 && a.same_process?(b),
       details(generation_known: a.generation_known?, same_process: a.same_process?(b))}
    end

    test("self_observe_lookup_generation_exact") do
      obs = ProcessHandle.observe(Process.pid)
      id = ProcessHandle.lookup(Process.pid) || raise "missing lookup"
      {obs.state.live? && obs.identity.try(&.same_process?(id)) == true,
       details(state: obs.state, same_process: obs.identity.try(&.same_process?(id)))}
    end

    test("pid_one_observation_is_not_false_dead") do
      obs = ProcessHandle.observe(1)
      {obs.state.live? || obs.state.unknown?, details(state: obs.state, identity: !obs.identity.nil?)}
    end

    test("lookup_reaped_pid_returns_nil") do
      child = child_sleep(90)
      reaped = false
      begin
        before = ProcessHandle.lookup(child.pid)
        status = child.wait
        reaped = true
        after = ProcessHandle.lookup(child.pid)
        {before != nil && status.success? && after.nil?, details(before: !before.nil?, after_nil: after.nil?)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("identity_alive_true_then_false_after_reap") do
      child = child_sleep(140)
      reaped = false
      begin
        identity = ProcessHandle.lookup(child.pid) || raise "missing child identity"
        live_before = identity.alive?
        status = child.wait
        reaped = true
        live_after = identity.alive?
        {live_before && status.success? && !live_after, details(live_before: live_before, live_after: live_after)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("stopped_child_is_present_and_live") do
      marker = File.join(workdir, "stopped-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "stop-self", marker])
      reaped = false
      begin
        raise "stop marker missing" unless wait_for_file(marker)
        sleep 60.milliseconds
        obs = ProcessHandle.observe(child.pid)
        id = ProcessHandle.lookup(child.pid)
        LibC.kill(child.pid.to_i32, Signal::CONT.value)
        status = child.wait
        reaped = true
        {obs.state.live? && id != nil && status.success?, details(state: obs.state, generation_known: id.try(&.generation_known?))}
      ensure
        LibC.kill(child.pid.to_i32, Signal::CONT.value) rescue nil
        cleanup(child, reaped)
      end
    end

    test("generation_stable_across_stop_continue") do
      marker = File.join(workdir, "stop-generation-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "stop-self", marker])
      reaped = false
      begin
        raise "stop marker missing" unless wait_for_file(marker)
        first = ProcessHandle.lookup(child.pid) || raise "missing stopped identity"
        LibC.kill(child.pid.to_i32, Signal::CONT.value)
        second = ProcessHandle.lookup(child.pid) || raise "missing continued identity"
        status = child.wait
        reaped = true
        {first.same_process?(second) && status.success?, details(same_process: first.same_process?(second))}
      ensure
        LibC.kill(child.pid.to_i32, Signal::CONT.value) rescue nil
        cleanup(child, reaped)
      end
    end

    test("raw_zombie_is_never_classified_live") do
      marker = File.join(workdir, "zombie-holder-#{Process.pid}.txt")
      holder = spawn_native_zombie_holder(marker, 23)
      reaped = false
      begin
        zombie_pid = wait_file_value(marker).to_i64
        obs = wait_for_observation(zombie_pid, 600.milliseconds) { |o| !o.state.live? }
        signal_present = pid_present_by_signal?(zombie_pid)
        zombie_capability = obs.state.zombie? ? "libproc-zombie-visible" : obs.state.unknown? ? "libproc-esrch-signal-present-unknown" : "unexpected-dead"
        valid_terminal = signal_present && (obs.state.zombie? || obs.state.unknown?)
        valid_identity = obs.state.zombie? ? (obs.identity.try(&.generation_known?) == true) : obs.identity.nil?
        status = holder.wait
        reaped = true
        after = ProcessHandle.observe(zombie_pid)
        {valid_terminal && valid_identity && status.success? && after.state.dead?,
         details(observed_state: obs.state, signal_present: signal_present, capability: zombie_capability, after: after.state,
           generation_known: obs.identity.try(&.generation_known?),
           note: "libproc ESRCH plus signal-proven PID presence is Unknown, not false Dead; exact Zombie requires a returned SZOMB snapshot")}
      ensure
        cleanup(holder, reaped)
      end
    end

    test("zombie_lookup_matches_observer_capability") do
      marker = File.join(workdir, "zombie-lookup-#{Process.pid}.txt")
      holder = spawn_native_zombie_holder(marker, 7)
      reaped = false
      begin
        zombie_pid = wait_file_value(marker).to_i64
        obs = wait_for_observation(zombie_pid, 600.milliseconds) { |o| !o.state.live? }
        signal_present = pid_present_by_signal?(zombie_pid)
        lookup = ProcessHandle.lookup(zombie_pid)
        same = obs.identity.try { |id| lookup.try { |other| id.same_process?(other) } }
        coherent = if obs.state.zombie?
                     lookup != nil && lookup.try(&.generation_known?) == true && same == true
                   else
                     obs.state.unknown? && signal_present && lookup.nil?
                   end
        status = holder.wait
        reaped = true
        {coherent && status.success?,
         details(observed_state: obs.state, signal_present: signal_present, lookup_present: lookup != nil, same_generation: same,
           generation_known: lookup.try(&.generation_known?),
           note: "lookup remains libproc identity-only; observe may retain Unknown presence when libproc hides an unreaped zombie")}
      ensure
        cleanup(holder, reaped)
      end
    end

    test("sigkill_child_dead_after_reap") do
      child = child_sleep(1800)
      reaped = false
      begin
        before = ProcessHandle.observe(child.pid)
        LibC.kill(child.pid.to_i32, Signal::KILL.value)
        status = child.wait
        reaped = true
        after = ProcessHandle.observe(child.pid)
        {before.state.live? && status.signal_exit? && status.exit_signal? == Signal::KILL && after.state.dead?,
         details(before: before.state, after: after.state, signal: status.exit_signal?)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("process_exists_and_observation_agree_live_then_dead") do
      child = child_sleep(180)
      reaped = false
      begin
        live_exists = Process.exists?(child.pid)
        live_obs = ProcessHandle.observe(child.pid)
        status = child.wait
        reaped = true
        dead_exists = Process.exists?(child.pid)
        dead_obs = ProcessHandle.observe(child.pid)
        {live_exists && live_obs.present? && status.success? && !dead_exists && dead_obs.state.dead?,
         details(live_exists: live_exists, live_state: live_obs.state, dead_exists: dead_exists, dead_state: dead_obs.state)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("rapid_exit_observation_never_live_after_reap") do
      false_live = 0
      24.times do
        child = child_sleep(25)
        reaped = false
        begin
          identity = ProcessHandle.lookup(child.pid)
          child.wait
          reaped = true
          obs = ProcessHandle.observe(child.pid)
          false_live += 1 if obs.state.live? || identity.try(&.alive?) == true
        ensure
          cleanup(child, reaped)
        end
      end
      {false_live == 0, details(iterations: 24, false_live: false_live)}
    end

    test("rapid_children_all_have_generation_tokens") do
      total = 32
      known = 0
      total.times do
        child = child_sleep(70)
        reaped = false
        begin
          identity = ProcessHandle.lookup(child.pid)
          known += 1 if identity.try(&.generation_known?) == true
          child.wait
          reaped = true
        ensure
          cleanup(child, reaped)
        end
      end
      {known == total, details(total: total, generation_known: known)}
    end

    test("native_thread_observation_start_gate") do
      baseline = ProcessHandle.lookup(Process.pid) || raise "missing self identity"
      ready = Atomic(Int32).new(0)
      go = Atomic(Bool).new(false)
      outcomes = Array(Int32).new(8, 0)
      threads = Array(Thread).new(8) do |index|
        Thread.new do
          ready.add(1)
          until go.get
            Thread.yield
          end
          matches = 0
          50.times do
            id = ProcessHandle.lookup(Process.pid)
            matches += 1 if id && baseline.same_process?(id)
          end
          outcomes[index] = matches
        end
      end
      raise "threads failed to rendezvous" unless wait_until(1.second) { ready.get == 8 }
      go.set(true)
      threads.each(&.join)
      {outcomes.all? { |n| n == 50 }, details(threads: 8, observations_each: 50, results: outcomes.join(","))}
    end

    test("concurrent_observe_lookup_exit_race_only_valid_states") do
      child = child_sleep(220)
      errors = Atomic(Int32).new(0)
      workers = Array(Thread).new(4) do
        Thread.new do
          80.times do
            begin
              obs = ProcessHandle.observe(child.pid)
              id = ProcessHandle.lookup(child.pid)
              valid = obs.state.live? || obs.state.zombie? || obs.state.dead? || obs.state.unknown?
              errors.add(1) unless valid
              errors.add(1) if obs.state.dead? && id != nil
            rescue ProcessHandle::Error::AccessDenied
            rescue
              errors.add(1)
            end
          end
        end
      end
      status = child.wait
      workers.each(&.join)
      child.close
      {status.success? && errors.get == 0, details(errors: errors.get)}
    end

    test("observe_lookup_churn_fd_count_bounded") do
      before = fd_count_observation
      500.times do
        ProcessHandle.observe(Process.pid)
        ProcessHandle.lookup(Process.pid)
      end
      after = fd_count_observation
      delta = before >= 0 && after >= 0 ? after - before : 0
      {before < 0 || after < 0 || delta.abs <= 2, details(before: before, after: after, delta: delta)}
    end
  end

  def self.run_deep_native_matrix : Nil
    test("kqueue_close_from_other_thread_is_bounded") do
      marker = File.join(workdir, "kq-close-wait-#{Process.pid}.json")
      helper = Process.new(self_exe, ["--child", "kqueue-close-wait-helper", marker])
      reaped = false
      begin
        status = helper.wait
        reaped = true
        payload = JSON.parse(File.read(marker))
        {status.success? && payload["register_rc"].as_i == 0,
         details(waiter_returned: payload["waiter_returned"], waiter_result: payload["waiter_result"],
           interpretation: "whether close wakes blocked kevent is recorded; helper process bounds any stuck native thread")}
      ensure
        cleanup(helper, reaped)
      end
    end

    test("kqueue_signal_coalescing_under_burst") do
      marker = File.join(workdir, "signal-burst-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "ignore-signal", marker, Signal::USR1.value.to_s])
      reaped = false
      begin
        raise "child not ready" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          reg, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL, EV_ADD | EV_CLEAR)
          5.times { LibC.kill(child.pid.to_i32, Signal::USR1.value) }
          first_rc, first, _ = kevent_next(kq, 500.milliseconds)
          second_rc, second, _ = kevent_next(kq, 80.milliseconds)
          child.terminate
          status = child.wait
          reaped = true
          {reg == 0 && first_rc == 1 && (first.fflags & NOTE_SIGNAL) != 0 && status.signal_exit?,
           details(first: decode_kevent(first).to_json, second_rc: second_rc,
             second: second_rc == 1 ? decode_kevent(second).to_json : "none", signals_sent: 5)}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_note_signal_low_bits_observation") do
      marker = File.join(workdir, "signal-bits-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "ignore-signal", marker, Signal::USR2.value.to_s])
      reaped = false
      begin
        raise "child not ready" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          reg, _, _ = kevent_register(kq, child.pid, NOTE_SIGNAL, EV_ADD | EV_ONESHOT)
          LibC.kill(child.pid.to_i32, Signal::USR2.value)
          event_rc, event, _ = kevent_next(kq, 500.milliseconds)
          child.terminate
          status = child.wait
          reaped = true
          {reg == 0 && event_rc == 1 && (event.fflags & NOTE_SIGNAL) != 0 && status.signal_exit?,
           decode_kevent(event).merge(details(low_bits: (event.fflags & 0x000f_ffff_u32), signal: Signal::USR2.value))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_bulk_receipts_for_two_valid_registrations") do
      a = child_sleep(650)
      b = child_sleep(650)
      reaped_a = false
      reaped_b = false
      kq = LibC.kqueue
      begin
        raise "kqueue failed" if kq < 0
        changes = StaticArray[
          LibC::Kevent.new(ident: a.pid.to_u64, filter: EVFILT_PROC, flags: EV_ADD | EV_RECEIPT, fflags: NOTE_EXIT, data: 0_i64, udata: Pointer(Void).new(0x31_u64)),
          LibC::Kevent.new(ident: b.pid.to_u64, filter: EVFILT_PROC, flags: EV_ADD | EV_RECEIPT, fflags: NOTE_EXIT, data: 0_i64, udata: Pointer(Void).new(0x32_u64)),
        ]
        receipts = StaticArray(LibC::Kevent, 2).new { LibC::Kevent.new }
        Errno.value = Errno::NONE
        rc = LibC.kevent(kq, changes.to_unsafe, 2, receipts.to_unsafe, 2, Pointer(LibC::Timespec).null)
        ok_receipts = rc == 2 && receipts.all? { |e| (e.flags & EV_ERROR) != 0 && e.data == 0 }
        a.terminate; b.terminate
        a.wait; reaped_a = true
        b.wait; reaped_b = true
        {ok_receipts, details(rc: rc, first_data: receipts[0].data, second_data: receipts[1].data,
          first_udata: receipts[0].udata.address.to_u64, second_udata: receipts[1].udata.address.to_u64)}
      ensure
        LibC.close(kq) if kq >= 0
        cleanup(a, reaped_a); cleanup(b, reaped_b)
      end
    end

    test("kqueue_zombie_note_exit_registration_race_classified") do
      marker = File.join(workdir, "zombie-exit-event-#{Process.pid}.txt")
      holder = spawn_native_zombie_holder(marker, 17)
      reaped = false
      begin
        zombie = wait_file_value(marker).to_i64
        obs = wait_for_observation(zombie, 600.milliseconds) { |o| o.terminated? }
        result = with_kqueue do |kq|
          reg, _, reg_errno = kevent_register(kq, zombie, NOTE_EXIT | NOTE_EXITSTATUS, EV_ADD | EV_ONESHOT)
          if reg == 0
            event_rc, event, event_errno = kevent_next(kq, 300.milliseconds)
            ok = event_rc == 1 && (event.fflags & NOTE_EXIT) != 0
            {ok, decode_kevent(event).merge(details(observed_state: obs.state, registration: "accepted",
              reg_errno: reg_errno, event_errno: event_errno))}
          else
            {reg_errno == Errno::ESRCH.value,
             details(observed_state: obs.state, registration: "esrch", reg_rc: reg, reg_errno: reg_errno,
               note: "registration may lose the race once Darwin has made the exited PID unavailable to EVFILT_PROC")}
          end
        end
        holder.wait; reaped = true
        result
      ensure
        cleanup(holder, reaped)
      end
    end

    test("kqueue_same_queue_two_waiters_one_oneshot_delivery") do
      child = child_sleep(260)
      reaped = false
      kq = LibC.kqueue
      begin
        raise "kqueue failed" if kq < 0
        reg, _, _ = kevent_register(kq, child.pid, NOTE_EXIT, EV_ADD | EV_ONESHOT)
        results = Array(Int32).new(2, -99)
        threads = Array(Thread).new(2) do |i|
          Thread.new do
            rc, _, _ = kevent_next(kq, 700.milliseconds)
            results[i] = rc
          end
        end
        threads.each(&.join)
        status = child.wait; reaped = true
        {reg == 0 && results.count(1) == 1 && results.count(0) == 1 && status.success?, details(results: results.join(","))}
      ensure
        LibC.close(kq) if kq >= 0
        cleanup(child, reaped)
      end
    end

    test("kqueue_exec_then_exit_reports_both_capabilities") do
      marker = File.join(workdir, "exec-sequence-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "exec-after", marker])
      reaped = false
      begin
        raise "exec child marker missing" unless wait_for_file(marker)
        result = with_kqueue do |kq|
          reg, _, _ = kevent_register(kq, child.pid, NOTE_EXEC | NOTE_EXIT, EV_ADD | EV_CLEAR)
          observed = 0_u32
          events = [] of String
          deadline = Time.instant + 2.seconds
          while Time.instant < deadline && (observed & (NOTE_EXEC | NOTE_EXIT)) != (NOTE_EXEC | NOTE_EXIT)
            rc, event, _ = kevent_next(kq, 500.milliseconds)
            if rc == 1
              observed |= event.fflags
              events << decode_kevent(event).to_json
            end
          end
          status = child.wait; reaped = true
          {reg == 0 && (observed & NOTE_EXEC) != 0 && (observed & NOTE_EXIT) != 0 && status.success?,
           details(observed_hex: observed.to_s(16), events: events.join(" | "))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("group_wait_empty_nil_natural_exit") do
      child, pgid, _ = spawn_group_child(180, "wait-natural")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        start = Time.instant
        drained = group.wait_empty
        elapsed = Time.instant - start
        status = child.wait; reaped = true
        {drained && status.success? && elapsed >= 50.milliseconds,
         details(drained: drained, elapsed_ms: elapsed.total_milliseconds)}
      ensure
        group.close rescue nil
        cleanup(child, reaped)
      end
    end

    test("group_wait_zero_live_then_dead") do
      child, pgid, _ = spawn_group_child(180, "wait-zero")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        live = group.wait_empty(Time::Span.zero)
        status = child.wait; reaped = true
        dead = group.wait_empty(Time::Span.zero)
        {(!live) && dead && status.success?, details(live_poll: live, dead_poll: dead)}
      ensure
        group.close rescue nil
        cleanup(child, reaped)
      end
    end

    test("group_wait_empty_many_concurrent_fibers") do
      child, pgid, _ = spawn_group_child(220, "wait-fanout")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        wait_results = Channel(Bool).new(12)
        12.times { spawn { wait_results.send(group.wait_empty(2.seconds)) } }
        values = Array(Bool).new(12) { wait_results.receive }
        status = child.wait; reaped = true
        {values.all? && status.success?, details(results: values.join(","))}
      ensure
        group.close rescue nil
        cleanup(child, reaped)
      end
    end

    test("group_wait_empty_from_raw_thread_with_child_reaper_progress") do
      child, pgid, _ = spawn_group_child(200, "wait-thread")
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        outcome = "unset"
        thread = Thread.new do
          begin
            outcome = group.wait_empty(2.seconds).to_s
          rescue ex
            outcome = "#{ex.class.name}:#{ex.message}"
          end
        end
        # The raw waiter can observe group state, but the owning Crystal Process
        # still supplies child-reaper progress. Reap before joining the waiter.
        status = child.wait
        reaped = true
        thread.join
        {outcome == "true" && status.success?, details(outcome: outcome,
          note: "result-before-join preserves Crystal child-reaper progress")}
      ensure
        group.close rescue nil
        cleanup(child, reaped)
      end
    end

    test("group_direct_terminate_ignored_then_kill") do
      child, pgid, _ = spawn_group_child(2600, "ignore-direct", true)
      reaped = false
      group = ProcessSupervision.process_group(pgid)
      begin
        group.terminate
        sleep 100.milliseconds
        still = ProcessHandle.observe(child.pid)
        group.kill
        status = child.wait; reaped = true
        {still.live? && status.exit_signal? == Signal::KILL && group.wait_empty(1.second),
         details(after_term: still.state, final_signal: status.exit_signal?)}
      ensure
        group.close rescue nil
        cleanup(child, reaped)
      end
    end

    test("setsid_creates_new_session_and_process_group") do
      marker = File.join(workdir, "setsid-direct-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "setsid-sleep", marker])
      reaped = false
      begin
        raise "setsid marker missing" unless wait_for_file(marker)
        parts = File.read(marker).split('|')
        pid = parts[0].to_i64; pgid = parts[1].to_i64; rc = parts[2].to_i64; sid = parts[3].to_i64
        child.terminate
        status = child.wait; reaped = true
        {rc == pid && pgid == pid && sid == pid && status.signal_exit?, details(pid: pid, pgid: pgid, sid: sid, setsid_rc: rc)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("spawn_clear_environment_can_be_effectively_empty") do
      marker = File.join(workdir, "clear-empty-#{Process.pid}.json")
      child = Process.new(self_exe, ["--child", "env-dump", marker, "PATH", "HOME", "SHELL"], clear_env: true)
      reaped = false
      begin
        status = child.wait; reaped = true
        payload = JSON.parse(File.read(marker))
        {status.success? && %w(PATH HOME SHELL).all? { |k| payload[k].raw.nil? }, details(payload: payload.to_json)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("spawn_delete_path_from_inherited_environment") do
      marker = File.join(workdir, "delete-path-#{Process.pid}.json")
      child = Process.new(self_exe, ["--child", "env-dump", marker, "PATH"], env: {"PATH" => nil})
      reaped = false
      begin
        status = child.wait; reaped = true
        payload = JSON.parse(File.read(marker))
        {status.success? && payload["PATH"].raw.nil?, details(path_present: !payload["PATH"].raw.nil?)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("spawn_stdio_closed_input_is_eof") do
      child = Process.new(self_exe, ["--child", "stdio"], input: Process::Redirect::Close,
        output: Process::Redirect::Pipe, error: Process::Redirect::Pipe)
      reaped = false
      begin
        stdout_data = child.output.gets_to_end
        stderr_data = child.error.gets_to_end
        status = child.wait; reaped = true
        {status.success? && stdout_data == "OUT:" && stderr_data == "ERR:", details(stdout: stdout_data, stderr: stderr_data)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("spawn_symlink_to_executable_runs") do
      dir = File.join(workdir, "symlink-exe-#{Process.pid}")
      Dir.mkdir_p(dir)
      link = File.join(dir, "probe-link")
      File.symlink(self_exe, link)
      child = Process.new(link, ["--child", "exit-code", "0"])
      reaped = false
      begin
        status = child.wait; reaped = true
        {status.success?, details(link: link)}
      ensure
        cleanup(child, reaped)
        File.delete(link) rescue nil
        Dir.delete(dir) rescue nil
      end
    end

    test("spawn_many_cloexec_descriptors_not_inherited") do
      files = [] of File
      markers = [] of String
      children = [] of Process
      reaped = [] of Bool
      begin
        12.times do |i|
          f = File.tempfile("process-probe-fd-#{i}")
          files << f
          flags = LibC.fcntl(f.fd, F_GETFD)
          LibC.fcntl(f.fd, F_SETFD, flags | FD_CLOEXEC)
          marker = File.join(workdir, "fd-many-#{Process.pid}-#{i}.txt")
          markers << marker
          children << Process.new(self_exe, ["--child", "fd-check", marker, f.fd.to_s])
          reaped << false
        end
        statuses = children.map_with_index do |c, i|
          st = c.wait; reaped[i] = true; st
        end
        visible = markers.count do |m|
          parts = File.read(m).split('|')
          parts[0].to_i >= 0
        end
        {statuses.all?(&.success?) && visible == 0, details(children: children.size, inherited: visible)}
      ensure
        children.each_with_index { |c, i| cleanup(c, reaped[i]) }
        files.each { |f| f.close rescue nil; File.delete(f.path) rescue nil }
      end
    end
  end

  def self.run_completion_matrix : Nil
    test("spawn_large_bidirectional_stdio_512k_without_deadlock") do
      child = Process.new(self_exe, ["--child", "stdio"],
        input: Process::Redirect::Pipe, output: Process::Redirect::Pipe, error: Process::Redirect::Pipe)
      payload = ("0123456789abcdef" * (512 * 1024 // 16))
      spawn do
        child.input << payload
        child.input.close
      end
      stdout_result = Channel(String).new(1)
      stderr_result = Channel(String).new(1)
      spawn { stdout_result.send(child.output.gets_to_end) }
      spawn { stderr_result.send(child.error.gets_to_end) }
      stdout_data = stdout_result.receive
      stderr_data = stderr_result.receive
      status = child.wait
      child.close
      {status.success? && stdout_data == "OUT:#{payload}" && stderr_data == "ERR:#{payload}",
       details(bytes: payload.bytesize, stdout_bytes: stdout_data.bytesize, stderr_bytes: stderr_data.bytesize)}
    end

    test("spawn_arguments_are_not_shell_interpreted") do
      side_effect = File.join(workdir, "shell-side-effect-#{Process.pid}")
      File.delete(side_effect) if File.exists?(side_effect)
      marker = File.join(workdir, "literal-args-#{Process.pid}.json")
      literal = "; touch #{side_effect} && $(echo nope) | `echo no`"
      child = Process.new(self_exe, ["--child", "args", marker, literal])
      status = child.wait; child.close
      payload = JSON.parse(File.read(marker))
      args = payload["args"].as_a.map(&.as_s)
      {status.success? && args == [literal] && !File.exists?(side_effect), details(args_exact: args == [literal], side_effect: File.exists?(side_effect))}
    end

    test("spawn_environment_keys_are_case_sensitive_on_darwin") do
      marker = File.join(workdir, "env-case-#{Process.pid}.json")
      child = Process.new(self_exe, ["--child", "env-dump", marker, "ProbeCase", "probecase"],
        env: {"ProbeCase" => "UPPER", "probecase" => "lower"})
      status = child.wait; child.close
      payload = JSON.parse(File.read(marker))
      {status.success? && payload["ProbeCase"].as_s? == "UPPER" && payload["probecase"].as_s? == "lower",
       details(upper: payload["ProbeCase"]?, lower: payload["probecase"]?)}
    end

    test("spawn_path_search_finds_executable_in_parent_path") do
      dir = File.join(workdir, "path-search-#{Process.pid}")
      Dir.mkdir_p(dir)
      link = File.join(dir, "process-probe-path-child")
      File.symlink(self_exe, link)
      old = ENV["PATH"]?
      begin
        ENV["PATH"] = dir
        child = Process.new("process-probe-path-child", ["--child", "exit-code", "31"])
        status = child.wait; child.close
        {status.exit_code? == 31, details(exit_code: status.exit_code?, path: dir)}
      ensure
        if old
          ENV["PATH"] = old
        else
          ENV.delete("PATH")
        end
        File.delete(link) rescue nil
        Dir.delete(dir) rescue nil
      end
    end

    test("spawn_shebang_script_executes_directly") do
      script = File.join(workdir, "shebang-#{Process.pid}.sh")
      File.write(script, "#!/bin/sh\nexit 37\n")
      File.chmod(script, 0o755)
      begin
        child = Process.new(script)
        status = child.wait; child.close
        {status.exit_code? == 37, details(exit_code: status.exit_code?)}
      ensure
        File.delete(script) rescue nil
      end
    end

    test("spawn_executable_text_without_shebang_reports_exec_error") do
      script = File.join(workdir, "enoexec-#{Process.pid}")
      File.write(script, "this is not an executable image\n")
      File.chmod(script, 0o755)
      outcome = "unexpected_success"
      child = nil.as(Process?)
      begin
        begin
          child = Process.new(script)
          status = child.wait
          outcome = "status:#{status.system_exit_status}"
        rescue ex
          outcome = "#{ex.class.name}:#{ex.message}"
        end
        {outcome != "unexpected_success" && !outcome.starts_with?("status:0"), details(outcome: outcome)}
      ensure
        child.try &.close rescue nil
        File.delete(script) rescue nil
      end
    end

    test("spawn_many_arguments_512_roundtrip") do
      marker = File.join(workdir, "many-args-#{Process.pid}.json")
      values = Array(String).new(512) { |i| "arg-#{i}-#{"x" * (i % 17)}" }
      child = Process.new(self_exe, ["--child", "args", marker] + values)
      status = child.wait; child.close
      got = JSON.parse(File.read(marker))["args"].as_a.map(&.as_s)
      {status.success? && got == values, details(count: got.size, exact: got == values)}
    end

    test("spawn_large_environment_400_entries_roundtrip") do
      marker = File.join(workdir, "many-env-#{Process.pid}.json")
      env = {} of String => String
      keys = [] of String
      400.times do |i|
        key = "PROCESS_PROBE_E#{i.to_s.rjust(3, '0')}"
        keys << key
        env[key] = "v#{i}-#{"z" * 32}"
      end
      child = Process.new(self_exe, ["--child", "env-dump", marker] + keys, env: env)
      status = child.wait; child.close
      got = JSON.parse(File.read(marker))
      exact = keys.all? { |k| got[k].as_s? == env[k]? }
      {status.success? && exact, details(count: keys.size, exact: exact)}
    end

    test("process_status_signal_reason_matrix") do
      matrix = {
        Signal::HUP  => Process::ExitReason::TerminalDisconnected,
        Signal::INT  => Process::ExitReason::Interrupted,
        Signal::TERM => Process::ExitReason::SessionEnded,
        Signal::ABRT => Process::ExitReason::Aborted,
        Signal::KILL => Process::ExitReason::Aborted,
      }
      outcomes = [] of String
      ok = true
      matrix.each do |signal, expected|
        child = Process.new(self_exe, ["--child", "self-signal", "60", signal.value.to_s])
        status = child.wait; child.close
        match = status.exit_signal? == signal && status.exit_reason == expected
        ok &&= match
        outcomes << "#{signal}:#{status.exit_reason}:#{status.exit_signal?}:#{match}"
      end
      {ok, details(outcomes: outcomes.join(" | "))}
    end

    test("kqueue_delete_missing_filter_receipt_reports_error") do
      kq = LibC.kqueue
      raise "kqueue failed" if kq < 0
      begin
        rc, event, errno = kevent_change(kq, Process.pid, EV_DELETE | EV_RECEIPT, NOTE_EXIT, receipt: true)
        has_error = rc == 1 && (event.flags & EV_ERROR) != 0 && event.data != 0
        {has_error, details(rc: rc, syscall_errno: errno, event_flags: event.flags.to_s(16), event_data: event.data)}
      ensure
        LibC.close(kq)
      end
    end

    test("kqueue_disabled_exit_becomes_visible_after_enable") do
      child = child_sleep(120)
      reaped = false
      kq = LibC.kqueue
      raise "kqueue failed" if kq < 0
      begin
        add_rc, _, add_errno = kevent_change(kq, child.pid, EV_ADD | EV_DISABLE, NOTE_EXIT)
        sleep 260.milliseconds
        en_rc, _, en_errno = kevent_change(kq, child.pid, EV_ENABLE, NOTE_EXIT)
        event_rc, event, event_errno = kevent_wait(kq, 1.second)
        status = child.wait; reaped = true
        ok = add_rc == 0 && en_rc == 0 && event_rc == 1 && event.ident == child.pid.to_u64 && (event.fflags & NOTE_EXIT) != 0 && status.success?
        {ok, details(add_rc: add_rc, add_errno: add_errno, enable_rc: en_rc, enable_errno: en_errno, event_rc: event_rc, event_errno: event_errno, event_fflags: event.fflags.to_s(16))}
      ensure
        LibC.close(kq)
        cleanup(child, reaped)
      end
    end

    test("kqueue_oneshot_filter_is_deleted_after_delivery") do
      Signal::USR1.ignore
      kq = LibC.kqueue
      raise "kqueue failed" if kq < 0
      begin
        add_rc, _, _ = kevent_change(kq, Process.pid, EV_ADD | EV_ONESHOT, NOTE_SIGNAL)
        LibC.kill(Process.pid, Signal::USR1.value)
        event_rc, event, _ = kevent_wait(kq, 1.second)
        del_rc, del_event, del_errno = kevent_change(kq, Process.pid, EV_DELETE | EV_RECEIPT, NOTE_SIGNAL, receipt: true)
        deleted = del_rc == 1 && (del_event.flags & EV_ERROR) != 0 && del_event.data != 0
        {add_rc == 0 && event_rc == 1 && (event.fflags & NOTE_SIGNAL) != 0 && deleted,
         details(event_rc: event_rc, delete_rc: del_rc, delete_errno: del_errno, delete_data: del_event.data)}
      ensure
        LibC.close(kq)
        Signal::USR1.reset
      end
    end
  end

  # Revision-6 parameter matrix helpers. Literal callers below keep each
  # parameter/interleaving independently attributable in the returned JSONL.
  def self.r6_exit_code_case(code : Int32)
    child = Process.new(self_exe, ["--child", "exit-code", code.to_s])
    reaped = false
    begin
      status = child.wait
      reaped = true
      {status.exit_code? == code, details(expected: code, actual: status.exit_code?, raw: status.system_exit_status)}
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_signal_exit_case(signal : Signal)
    child = Process.new(self_exe, ["--child", "self-signal", "30", signal.value.to_s])
    reaped = false
    begin
      status = child.wait
      reaped = true
      {status.exit_signal? == signal, details(expected: signal, actual: status.exit_signal?, raw: status.system_exit_status)}
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_spawn_argument_case(value : String, label : String)
    marker = File.join(workdir, "r6-mac-arg-#{label}-#{Process.pid}-#{Random.rand(1_000_000)}.json")
    child = Process.new(self_exe, ["--child", "args", marker, value])
    reaped = false
    begin
      status = child.wait
      reaped = true
      actual = JSON.parse(File.read(marker))["args"].as_a.map(&.as_s)
      {status.success? && actual == [value], details(expected_bytes: value.bytesize, actual_bytes: actual.first?.try(&.bytesize), exact: actual == [value])}
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_spawn_environment_case(key : String, value : String, label : String, clear_env : Bool = false)
    marker = File.join(workdir, "r6-mac-env-#{label}-#{Process.pid}-#{Random.rand(1_000_000)}.json")
    child = Process.new(self_exe, ["--child", "env-dump", marker, key], env: {key => value}, clear_env: clear_env)
    reaped = false
    begin
      status = child.wait
      reaped = true
      actual = JSON.parse(File.read(marker))[key]?.try(&.as_s?)
      {status.success? && actual == value, details(key: key, expected_bytes: value.bytesize, actual_bytes: actual.try(&.bytesize), clear_env: clear_env)}
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_kqueue_exit_code_case(code : Int32)
    child = Process.new(self_exe, ["--child", "delayed-exit-code", "80", code.to_s])
    reaped = false
    begin
      result = with_kqueue do |kq|
        reg_rc, _, reg_errno = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
        event_rc, event, event_errno = kevent_next(kq, 2.seconds)
        status = child.wait
        reaped = true
        ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXIT) != 0 &&
             (event.fflags & NOTE_EXITSTATUS) != 0 && event.data.to_u32 == status.system_exit_status && status.exit_code? == code
        {ok, decode_kevent(event).merge(details(expected: code, actual: status.exit_code?, reg_errno: reg_errno, event_errno: event_errno))}
      end
      result
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_kqueue_signal_case(signal : Signal)
    child = Process.new(self_exe, ["--child", "self-signal", "80", signal.value.to_s])
    reaped = false
    begin
      result = with_kqueue do |kq|
        reg_rc, _, reg_errno = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
        event_rc, event, event_errno = kevent_next(kq, 2.seconds)
        status = child.wait
        reaped = true
        ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXIT) != 0 &&
             event.data.to_u32 == status.system_exit_status && status.exit_signal? == signal
        {ok, decode_kevent(event).merge(details(expected: signal, actual: status.exit_signal?, reg_errno: reg_errno, event_errno: event_errno))}
      end
      result
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_kqueue_watcher_fanout_case(count : Int32)
    child = Process.new(self_exe, ["--child", "delayed-exit-code", "120", "17"])
    reaped = false
    queues = [] of Int32
    begin
      count.times do
        kq = LibC.kqueue
        raise "kqueue failed" if kq < 0
        queues << kq
        rc, _, errno = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
        raise "kevent registration failed: #{errno}" if rc != 0
      end
      delivered = queues.count do |kq|
        rc, event, _ = kevent_next(kq, 2.seconds)
        rc == 1 && (event.fflags & NOTE_EXIT) != 0 && event.ident == child.pid.to_u64
      end
      status = child.wait
      reaped = true
      {delivered == count && status.exit_code? == 17, details(watchers: count, delivered: delivered, exit: status.exit_code?)}
    ensure
      queues.each { |kq| LibC.close(kq) rescue nil }
      cleanup(child, reaped)
    end
  end

  def self.r6_kqueue_many_children_case(count : Int32)
    children = [] of Process
    reaped = [] of Bool
    begin
      result = with_kqueue do |kq|
        # Register each child right after it starts. The children exit 90-162 ms after their own start and
        # spawning many Crystal processes in a row takes longer than that on a loaded runner; a registration
        # for a child that has already exited fails with ESRCH (explore/macos/kqueue_zombie.c, 200/200).
        registrations = 0
        count.times do |i|
          child = Process.new(self_exe, ["--child", "delayed-exit-code", (90 + (i % 7) * 12).to_s, (i % 200).to_s])
          children << child
          reaped << false
          rc, _, _ = kevent_register(kq, child.pid, NOTE_EXIT, EV_ADD | EV_ONESHOT)
          registrations += 1 if rc == 0
        end
        seen = Set(UInt64).new
        deadline = Time.instant + 5.seconds
        while seen.size < count && Time.instant < deadline
          rc, event, _ = kevent_next(kq, 500.milliseconds)
          seen << event.ident if rc == 1 && (event.fflags & NOTE_EXIT) != 0
        end
        statuses = children.map_with_index do |child, i|
          s = child.wait
          reaped[i] = true
          s
        end
        {registrations == count && seen.size == count && statuses.all?(&.normal_exit?),
         details(children: count, registrations: registrations, unique_events: seen.size)}
      end
      result
    ensure
      children.each_with_index { |child, i| cleanup(child, reaped[i]) }
    end
  end

  def self.r6_observer_fiber_fanout_case(count : Int32)
    results = Channel(Bool).new(count)
    count.times do
      spawn do
        ok = true
        25.times do
          obs = ProcessHandle.observe(Process.pid)
          id = ProcessHandle.lookup(Process.pid)
          ok &&= obs.live? && id != nil && obs.identity.try { |mine| id.try { |other| mine.same_process?(other) } } == true
        end
        results.send(ok)
      end
    end
    values = Array(Bool).new(count) { results.receive }
    {values.all?, details(workers: count, successful: values.count(true), reads_per_worker: 25)}
  end

  def self.r6_observer_thread_fanout_case(count : Int32)
    results = Channel(Bool).new(count)
    count.times do
      Thread.new do
        ok = true
        25.times do
          obs = ProcessHandle.observe(Process.pid)
          id = ProcessHandle.lookup(Process.pid)
          ok &&= obs.live? && id != nil && obs.identity.try { |mine| id.try { |other| mine.same_process?(other) } } == true
        end
        results.send(ok)
      end
    end
    values = Array(Bool).new(count) { results.receive }
    Thread.sleep(15.milliseconds)
    {values.all?, details(workers: count, successful: values.count(true), reads_per_worker: 25)}
  end

  def self.r6_rapid_child_identity_case(count : Int32)
    good = 0
    count.times do
      child = child_sleep(35)
      reaped = false
      begin
        id = ProcessHandle.lookup(child.pid)
        status = child.wait
        reaped = true
        dead = ProcessHandle.observe(child.pid)
        good += 1 if id.try(&.generation_known?) == true && status.success? && dead.state.dead?
      ensure
        cleanup(child, reaped)
      end
    end
    {good == count, details(children: count, successful: good)}
  end

  def self.r6_group_member_count_case(count : Int32)
    leader, pgid, _ = spawn_group_child(2400, "r6-members-#{count}")
    members = [leader]
    reaped = Array(Bool).new(count, false)
    group = nil.as(ProcessSupervision::Group?)
    begin
      (count - 1).times do |i|
        marker = File.join(workdir, "r6-join-#{count}-#{i}-#{Process.pid}-#{Random.rand(1_000_000)}.txt")
        child = Process.new(self_exe, ["--child", "join-group-sleep", pgid.to_s, marker, "2400"])
        raise "joining child not ready" unless wait_for_file(marker)
        fields = File.read(marker).split('|')
        raise "joining child failed" unless fields[1].to_i64 == pgid && fields[2] == "0"
        members << child
      end
      group = ProcessSupervision.process_group(pgid)
      initially_populated = !group.empty?
      group.terminate
      statuses = members.map_with_index do |child, i|
        s = child.wait
        reaped[i] = true
        s
      end
      drained = group.wait_empty(2.seconds)
      {initially_populated && drained && statuses.all? { |s| s.exit_signal? == Signal::TERM },
       details(members: count, drained: drained, signals: statuses.map(&.exit_signal?).join(","))}
    ensure
      group.try &.close
      members.each_with_index { |child, i| cleanup(child, reaped[i]) }
    end
  end

  def self.r6_group_shutdown_case(grace_ms : Int32, ignore_term : Bool)
    child, pgid, _ = spawn_group_child(3000, "r6-shutdown-#{grace_ms}-#{ignore_term}", ignore_term)
    reaped = false
    group = ProcessSupervision.process_group(pgid)
    begin
      report = group.shutdown(grace: grace_ms.milliseconds, kill_after: 2.seconds, close: false)
      status = child.wait
      reaped = true
      expected_signal = ignore_term || grace_ms == 0 ? nil : Signal::TERM
      valid_signal = if ignore_term
                       status.exit_signal? == Signal::KILL
                     elsif grace_ms == 0
                       status.exit_signal?.in?({Signal::TERM, Signal::KILL})
                     else
                       status.exit_signal? == Signal::TERM
                     end
      {report.terminate_requested? && report.drained? && valid_signal && (!ignore_term || report.kill_requested?),
       details(grace_ms: grace_ms, ignore_term: ignore_term, terminate: report.terminate_requested?, kill: report.kill_requested?, signal: status.exit_signal?)}
    ensure
      group.close rescue nil
      cleanup(child, reaped)
    end
  end

  def self.r6_kqueue_registration_delay_case(delay_ms : Int32)
    child = Process.new(self_exe, ["--child", "delayed-exit-code", "90", "23"])
    reaped = false
    begin
      sleep delay_ms.milliseconds if delay_ms > 0
      result = with_kqueue do |kq|
        reg_rc, _, reg_errno = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
        event_rc = 0
        event = LibC::Kevent.new
        event_errno = 0
        if reg_rc == 0
          event_rc, event, event_errno = kevent_next(kq, 2.seconds)
        end
        status = child.wait
        reaped = true
        event_path = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXIT) != 0
        gone_path = reg_rc < 0 && reg_errno == Errno::ESRCH.value
        {event_path || gone_path,
         details(delay_ms: delay_ms, reg_rc: reg_rc, reg_errno: reg_errno, event_rc: event_rc, event_errno: event_errno, exit: status.exit_code?)}
      end
      result
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_kqueue_churn_case(cycles : Int32)
    before = fd_count_observation
    cycles.times do
      kq = LibC.kqueue
      raise "kqueue failed" if kq < 0
      LibC.close(kq)
    end
    after = fd_count_observation
    delta = (before >= 0 && after >= 0) ? after - before : 0
    {before < 0 || after < 0 || delta.abs <= 3, details(cycles: cycles, before: before, after: after, delta: delta)}
  end

  def self.r6_observation_churn_case(reads : Int32)
    first = ProcessHandle.lookup(Process.pid) || raise "self identity unavailable"
    mismatches = 0
    reads.times do
      obs = ProcessHandle.observe(Process.pid)
      id = ProcessHandle.lookup(Process.pid)
      mismatches += 1 unless obs.live? && id.try { |other| first.same_process?(other) } == true
    end
    {mismatches == 0, details(reads: reads, mismatches: mismatches)}
  end

  def self.r6_spawn_failure_churn_case(cycles : Int32)
    gc_settle
    before = fd_count_observation
    failures = 0
    cycles.times do |i|
      begin
        Process.new(File.join(workdir, "r6-missing-#{cycles}-#{i}"))
      rescue
        failures += 1
      end
    end
    after_no_gc = fd_count_observation
    gc_settle
    after = fd_count_observation
    delta = (before >= 0 && after >= 0) ? after - before : 0
    lingering = (before >= 0 && after_no_gc >= 0) ? after_no_gc - before : 0
    {failures == cycles && (before < 0 || after < 0 || delta.abs <= 3),
     details(cycles: cycles, failures: failures, before: before, after: after, delta: delta, after_no_gc: after_no_gc, lingering_until_gc: lingering)}
  end

  def self.run_r6_matrix : Nil
    test("r6_exit_code_000") do
      r6_exit_code_case(0)
    end

    test("r6_exit_code_001") do
      r6_exit_code_case(1)
    end

    test("r6_exit_code_002") do
      r6_exit_code_case(2)
    end

    test("r6_exit_code_003") do
      r6_exit_code_case(3)
    end

    test("r6_exit_code_007") do
      r6_exit_code_case(7)
    end

    test("r6_exit_code_008") do
      r6_exit_code_case(8)
    end

    test("r6_exit_code_015") do
      r6_exit_code_case(15)
    end

    test("r6_exit_code_031") do
      r6_exit_code_case(31)
    end

    test("r6_exit_code_032") do
      r6_exit_code_case(32)
    end

    test("r6_exit_code_042") do
      r6_exit_code_case(42)
    end

    test("r6_exit_code_063") do
      r6_exit_code_case(63)
    end

    test("r6_exit_code_064") do
      r6_exit_code_case(64)
    end

    test("r6_exit_code_065") do
      r6_exit_code_case(65)
    end

    test("r6_exit_code_070") do
      r6_exit_code_case(70)
    end

    test("r6_exit_code_073") do
      r6_exit_code_case(73)
    end

    test("r6_exit_code_074") do
      r6_exit_code_case(74)
    end

    test("r6_exit_code_075") do
      r6_exit_code_case(75)
    end

    test("r6_exit_code_078") do
      r6_exit_code_case(78)
    end

    test("r6_exit_code_100") do
      r6_exit_code_case(100)
    end

    test("r6_exit_code_125") do
      r6_exit_code_case(125)
    end

    test("r6_exit_code_126") do
      r6_exit_code_case(126)
    end

    test("r6_exit_code_127") do
      r6_exit_code_case(127)
    end

    test("r6_exit_code_128") do
      r6_exit_code_case(128)
    end

    test("r6_exit_code_137") do
      r6_exit_code_case(137)
    end

    test("r6_exit_code_200") do
      r6_exit_code_case(200)
    end

    test("r6_exit_code_254") do
      r6_exit_code_case(254)
    end

    test("r6_exit_code_255") do
      r6_exit_code_case(255)
    end

    test("r6_signal_exit_hup") do
      r6_signal_exit_case(Signal::HUP)
    end

    test("r6_signal_exit_int") do
      r6_signal_exit_case(Signal::INT)
    end

    test("r6_signal_exit_quit") do
      r6_signal_exit_case(Signal::QUIT)
    end

    test("r6_signal_exit_abrt") do
      r6_signal_exit_case(Signal::ABRT)
    end

    test("r6_signal_exit_kill") do
      r6_signal_exit_case(Signal::KILL)
    end

    test("r6_signal_exit_pipe") do
      r6_signal_exit_case(Signal::PIPE)
    end

    test("r6_signal_exit_alrm") do
      r6_signal_exit_case(Signal::ALRM)
    end

    test("r6_signal_exit_term") do
      r6_signal_exit_case(Signal::TERM)
    end

    test("r6_signal_exit_usr1") do
      r6_signal_exit_case(Signal::USR1)
    end

    test("r6_signal_exit_usr2") do
      r6_signal_exit_case(Signal::USR2)
    end

    test("r6_spawn_argument_00") do
      r6_spawn_argument_case("a", "0")
    end

    test("r6_spawn_argument_01") do
      r6_spawn_argument_case("abc", "1")
    end

    test("r6_spawn_argument_02") do
      r6_spawn_argument_case(" ", "2")
    end

    test("r6_spawn_argument_03") do
      r6_spawn_argument_case("  leading", "3")
    end

    test("r6_spawn_argument_04") do
      r6_spawn_argument_case("trailing  ", "4")
    end

    test("r6_spawn_argument_05") do
      r6_spawn_argument_case("both sides", "5")
    end

    test("r6_spawn_argument_06") do
      r6_spawn_argument_case("a b", "6")
    end

    test("r6_spawn_argument_07") do
      r6_spawn_argument_case("a  b", "7")
    end

    test("r6_spawn_argument_08") do
      r6_spawn_argument_case("a\tb", "8")
    end

    test("r6_spawn_argument_09") do
      r6_spawn_argument_case("a\nb", "9")
    end

    test("r6_spawn_argument_10") do
      r6_spawn_argument_case("\t", "10")
    end

    test("r6_spawn_argument_11") do
      r6_spawn_argument_case("\n", "11")
    end

    test("r6_spawn_argument_12") do
      r6_spawn_argument_case("\"", "12")
    end

    test("r6_spawn_argument_13") do
      r6_spawn_argument_case("\"quoted\"", "13")
    end

    test("r6_spawn_argument_14") do
      r6_spawn_argument_case("a\"b", "14")
    end

    test("r6_spawn_argument_15") do
      r6_spawn_argument_case("a\"\"b", "15")
    end

    test("r6_spawn_argument_16") do
      r6_spawn_argument_case("\\", "16")
    end

    test("r6_spawn_argument_17") do
      r6_spawn_argument_case("\\\\", "17")
    end

    test("r6_spawn_argument_18") do
      r6_spawn_argument_case("trailing\\", "18")
    end

    test("r6_spawn_argument_19") do
      r6_spawn_argument_case("trailing\\\\", "19")
    end

    test("r6_spawn_argument_20") do
      r6_spawn_argument_case("\\\"", "20")
    end

    test("r6_spawn_argument_21") do
      r6_spawn_argument_case("\\\\\"", "21")
    end

    test("r6_spawn_argument_22") do
      r6_spawn_argument_case("a\\\"b", "22")
    end

    test("r6_spawn_argument_23") do
      r6_spawn_argument_case("a\\\\\"b", "23")
    end

    test("r6_spawn_argument_24") do
      r6_spawn_argument_case("C:\\path with spaces\\", "24")
    end

    test("r6_spawn_argument_25") do
      r6_spawn_argument_case("C:\\endslash\\", "25")
    end

    test("r6_spawn_argument_26") do
      r6_spawn_argument_case("--flag=value", "26")
    end

    test("r6_spawn_argument_27") do
      r6_spawn_argument_case("--flag=\"quoted value\"", "27")
    end

    test("r6_spawn_argument_28") do
      r6_spawn_argument_case("single'quote", "28")
    end

    test("r6_spawn_argument_29") do
      r6_spawn_argument_case("semi;colon", "29")
    end

    test("r6_spawn_argument_30") do
      r6_spawn_argument_case("amp&ersand", "30")
    end

    test("r6_spawn_argument_31") do
      r6_spawn_argument_case("pipe|char", "31")
    end

    test("r6_spawn_argument_32") do
      r6_spawn_argument_case("caret^char", "32")
    end

    test("r6_spawn_argument_33") do
      r6_spawn_argument_case("percent%char", "33")
    end

    test("r6_spawn_argument_34") do
      r6_spawn_argument_case("bang!char", "34")
    end

    test("r6_spawn_argument_35") do
      r6_spawn_argument_case("paren(value)", "35")
    end

    test("r6_spawn_argument_36") do
      r6_spawn_argument_case("snowman-☃", "36")
    end

    test("r6_spawn_argument_37") do
      r6_spawn_argument_case("emoji-😀", "37")
    end

    test("r6_spawn_argument_38") do
      r6_spawn_argument_case("cjk-日本語", "38")
    end

    test("r6_spawn_argument_39") do
      r6_spawn_argument_case("rtl-مرحبا", "39")
    end

    test("r6_spawn_argument_40") do
      r6_spawn_argument_case("combining-é", "40")
    end

    test("r6_spawn_argument_41") do
      r6_spawn_argument_case("math-∑≈√", "41")
    end

    test("r6_spawn_argument_42") do
      r6_spawn_argument_case("nbsp- -x", "42")
    end

    test("r6_spawn_argument_43") do
      r6_spawn_argument_case("zero-width-​-x", "43")
    end

    test("r6_spawn_argument_44") do
      r6_spawn_argument_case("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "44")
    end

    test("r6_spawn_argument_45") do
      r6_spawn_argument_case("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "45")
    end

    test("r6_spawn_argument_46") do
      r6_spawn_argument_case("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "46")
    end

    test("r6_spawn_argument_47") do
      r6_spawn_argument_case("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "47")
    end

    test("r6_spawn_argument_48") do
      r6_spawn_argument_case("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "48")
    end

    test("r6_spawn_environment_00") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_00", "", "0")
    end

    test("r6_spawn_environment_01") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_01", "x", "1")
    end

    test("r6_spawn_environment_02") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_02", "a b", "2")
    end

    test("r6_spawn_environment_03") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_03", "  spaced  ", "3")
    end

    test("r6_spawn_environment_04") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_04", "a\tb", "4")
    end

    test("r6_spawn_environment_05") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_05", "a\nb", "5")
    end

    test("r6_spawn_environment_06") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_06", "\"quoted\"", "6")
    end

    test("r6_spawn_environment_07") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_07", "\\", "7")
    end

    test("r6_spawn_environment_08") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_08", "C:\\path\\value", "8")
    end

    test("r6_spawn_environment_09") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_09", "100%", "9")
    end

    test("r6_spawn_environment_10") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_10", "a=b", "10")
    end

    test("r6_spawn_environment_11") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_11", "semi;colon", "11")
    end

    test("r6_spawn_environment_12") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_12", "amp&ersand", "12")
    end

    test("r6_spawn_environment_13") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_13", "snowman-☃", "13")
    end

    test("r6_spawn_environment_14") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_14", "emoji-😀", "14")
    end

    test("r6_spawn_environment_15") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_15", "日本語", "15")
    end

    test("r6_spawn_environment_16") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_16", "مرحبا", "16")
    end

    test("r6_spawn_environment_17") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_17", "é", "17")
    end

    test("r6_spawn_environment_18") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_18", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "18")
    end

    test("r6_spawn_environment_19") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_19", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "19")
    end

    test("r6_spawn_environment_20") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_20", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "20")
    end

    test("r6_spawn_environment_21") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_ENV_21", "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "21")
    end

    test("r6_spawn_clear_environment_00") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_CLEAR_00", "x", "c0", true)
    end

    test("r6_spawn_clear_environment_01") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_CLEAR_01", "", "c1", true)
    end

    test("r6_spawn_clear_environment_02") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_CLEAR_02", "unicode-😀", "c2", true)
    end

    test("r6_spawn_clear_environment_03") do
      r6_spawn_environment_case("PROCESS_PROBE_R6_CLEAR_03", "value with spaces", "c3", true)
    end

    test("r6_kqueue_exitstatus_000") do
      r6_kqueue_exit_code_case(0)
    end

    test("r6_kqueue_exitstatus_001") do
      r6_kqueue_exit_code_case(1)
    end

    test("r6_kqueue_exitstatus_002") do
      r6_kqueue_exit_code_case(2)
    end

    test("r6_kqueue_exitstatus_003") do
      r6_kqueue_exit_code_case(3)
    end

    test("r6_kqueue_exitstatus_007") do
      r6_kqueue_exit_code_case(7)
    end

    test("r6_kqueue_exitstatus_008") do
      r6_kqueue_exit_code_case(8)
    end

    test("r6_kqueue_exitstatus_015") do
      r6_kqueue_exit_code_case(15)
    end

    test("r6_kqueue_exitstatus_031") do
      r6_kqueue_exit_code_case(31)
    end

    test("r6_kqueue_exitstatus_042") do
      r6_kqueue_exit_code_case(42)
    end

    test("r6_kqueue_exitstatus_064") do
      r6_kqueue_exit_code_case(64)
    end

    test("r6_kqueue_exitstatus_065") do
      r6_kqueue_exit_code_case(65)
    end

    test("r6_kqueue_exitstatus_070") do
      r6_kqueue_exit_code_case(70)
    end

    test("r6_kqueue_exitstatus_073") do
      r6_kqueue_exit_code_case(73)
    end

    test("r6_kqueue_exitstatus_074") do
      r6_kqueue_exit_code_case(74)
    end

    test("r6_kqueue_exitstatus_075") do
      r6_kqueue_exit_code_case(75)
    end

    test("r6_kqueue_exitstatus_078") do
      r6_kqueue_exit_code_case(78)
    end

    test("r6_kqueue_exitstatus_100") do
      r6_kqueue_exit_code_case(100)
    end

    test("r6_kqueue_exitstatus_125") do
      r6_kqueue_exit_code_case(125)
    end

    test("r6_kqueue_exitstatus_127") do
      r6_kqueue_exit_code_case(127)
    end

    test("r6_kqueue_exitstatus_255") do
      r6_kqueue_exit_code_case(255)
    end

    test("r6_kqueue_signal_hup") do
      r6_kqueue_signal_case(Signal::HUP)
    end

    test("r6_kqueue_signal_int") do
      r6_kqueue_signal_case(Signal::INT)
    end

    test("r6_kqueue_signal_quit") do
      r6_kqueue_signal_case(Signal::QUIT)
    end

    test("r6_kqueue_signal_abrt") do
      r6_kqueue_signal_case(Signal::ABRT)
    end

    test("r6_kqueue_signal_kill") do
      r6_kqueue_signal_case(Signal::KILL)
    end

    test("r6_kqueue_signal_pipe") do
      r6_kqueue_signal_case(Signal::PIPE)
    end

    test("r6_kqueue_signal_alrm") do
      r6_kqueue_signal_case(Signal::ALRM)
    end

    test("r6_kqueue_signal_term") do
      r6_kqueue_signal_case(Signal::TERM)
    end

    test("r6_kqueue_signal_usr1") do
      r6_kqueue_signal_case(Signal::USR1)
    end

    test("r6_kqueue_signal_usr2") do
      r6_kqueue_signal_case(Signal::USR2)
    end

    test("r6_kqueue_watcher_fanout_01") do
      r6_kqueue_watcher_fanout_case(1)
    end

    test("r6_kqueue_watcher_fanout_02") do
      r6_kqueue_watcher_fanout_case(2)
    end

    test("r6_kqueue_watcher_fanout_04") do
      r6_kqueue_watcher_fanout_case(4)
    end

    test("r6_kqueue_watcher_fanout_08") do
      r6_kqueue_watcher_fanout_case(8)
    end

    test("r6_kqueue_watcher_fanout_16") do
      r6_kqueue_watcher_fanout_case(16)
    end

    test("r6_kqueue_many_children_01") do
      r6_kqueue_many_children_case(1)
    end

    test("r6_kqueue_many_children_02") do
      r6_kqueue_many_children_case(2)
    end

    test("r6_kqueue_many_children_04") do
      r6_kqueue_many_children_case(4)
    end

    test("r6_kqueue_many_children_08") do
      r6_kqueue_many_children_case(8)
    end

    test("r6_kqueue_many_children_16") do
      r6_kqueue_many_children_case(16)
    end

    test("r6_kqueue_many_children_32") do
      r6_kqueue_many_children_case(32)
    end

    test("r6_observer_fiber_fanout_01") do
      r6_observer_fiber_fanout_case(1)
    end

    test("r6_observer_fiber_fanout_02") do
      r6_observer_fiber_fanout_case(2)
    end

    test("r6_observer_fiber_fanout_04") do
      r6_observer_fiber_fanout_case(4)
    end

    test("r6_observer_fiber_fanout_08") do
      r6_observer_fiber_fanout_case(8)
    end

    test("r6_observer_fiber_fanout_16") do
      r6_observer_fiber_fanout_case(16)
    end

    test("r6_observer_fiber_fanout_32") do
      r6_observer_fiber_fanout_case(32)
    end

    test("r6_observer_thread_fanout_01") do
      r6_observer_thread_fanout_case(1)
    end

    test("r6_observer_thread_fanout_02") do
      r6_observer_thread_fanout_case(2)
    end

    test("r6_observer_thread_fanout_04") do
      r6_observer_thread_fanout_case(4)
    end

    test("r6_observer_thread_fanout_08") do
      r6_observer_thread_fanout_case(8)
    end

    test("r6_observer_thread_fanout_16") do
      r6_observer_thread_fanout_case(16)
    end

    test("r6_rapid_child_identity_01") do
      r6_rapid_child_identity_case(1)
    end

    test("r6_rapid_child_identity_04") do
      r6_rapid_child_identity_case(4)
    end

    test("r6_rapid_child_identity_16") do
      r6_rapid_child_identity_case(16)
    end

    test("r6_rapid_child_identity_64") do
      r6_rapid_child_identity_case(64)
    end

    test("r6_group_member_count_01") do
      r6_group_member_count_case(1)
    end

    test("r6_group_member_count_02") do
      r6_group_member_count_case(2)
    end

    test("r6_group_member_count_04") do
      r6_group_member_count_case(4)
    end

    test("r6_group_member_count_08") do
      r6_group_member_count_case(8)
    end

    test("r6_group_member_count_16") do
      r6_group_member_count_case(16)
    end

    test("r6_group_shutdown_grace_000ms") do
      r6_group_shutdown_case(0, false)
    end

    test("r6_group_shutdown_ignore_term_000ms") do
      r6_group_shutdown_case(0, true)
    end

    test("r6_group_shutdown_grace_001ms") do
      r6_group_shutdown_case(1, false)
    end

    test("r6_group_shutdown_ignore_term_001ms") do
      r6_group_shutdown_case(1, true)
    end

    test("r6_group_shutdown_grace_010ms") do
      r6_group_shutdown_case(10, false)
    end

    test("r6_group_shutdown_ignore_term_010ms") do
      r6_group_shutdown_case(10, true)
    end

    test("r6_group_shutdown_grace_050ms") do
      r6_group_shutdown_case(50, false)
    end

    test("r6_group_shutdown_ignore_term_050ms") do
      r6_group_shutdown_case(50, true)
    end

    test("r6_group_shutdown_grace_200ms") do
      r6_group_shutdown_case(200, false)
    end

    test("r6_group_shutdown_ignore_term_200ms") do
      r6_group_shutdown_case(200, true)
    end

    test("r6_kqueue_registration_delay_000ms") do
      r6_kqueue_registration_delay_case(0)
    end

    test("r6_kqueue_registration_delay_001ms") do
      r6_kqueue_registration_delay_case(1)
    end

    test("r6_kqueue_registration_delay_002ms") do
      r6_kqueue_registration_delay_case(2)
    end

    test("r6_kqueue_registration_delay_005ms") do
      r6_kqueue_registration_delay_case(5)
    end

    test("r6_kqueue_registration_delay_010ms") do
      r6_kqueue_registration_delay_case(10)
    end

    test("r6_kqueue_registration_delay_025ms") do
      r6_kqueue_registration_delay_case(25)
    end

    test("r6_kqueue_registration_delay_050ms") do
      r6_kqueue_registration_delay_case(50)
    end

    test("r6_kqueue_registration_delay_100ms") do
      r6_kqueue_registration_delay_case(100)
    end

    test("r6_kqueue_registration_delay_150ms") do
      r6_kqueue_registration_delay_case(150)
    end

    test("r6_kqueue_churn_001") do
      r6_kqueue_churn_case(1)
    end

    test("r6_kqueue_churn_010") do
      r6_kqueue_churn_case(10)
    end

    test("r6_kqueue_churn_050") do
      r6_kqueue_churn_case(50)
    end

    test("r6_kqueue_churn_100") do
      r6_kqueue_churn_case(100)
    end

    test("r6_kqueue_churn_250") do
      r6_kqueue_churn_case(250)
    end

    test("r6_observation_churn_0010") do
      r6_observation_churn_case(10)
    end

    test("r6_observation_churn_0100") do
      r6_observation_churn_case(100)
    end

    test("r6_observation_churn_0500") do
      r6_observation_churn_case(500)
    end

    test("r6_observation_churn_1000") do
      r6_observation_churn_case(1000)
    end

    test("r6_spawn_failure_churn_001") do
      r6_spawn_failure_churn_case(1)
    end

    test("r6_spawn_failure_churn_010") do
      r6_spawn_failure_churn_case(10)
    end

    test("r6_spawn_failure_churn_050") do
      r6_spawn_failure_churn_case(50)
    end

    test("r6_spawn_failure_churn_100") do
      r6_spawn_failure_churn_case(100)
    end
  end

  def self.r9_mixed_concurrent_spawn_case(count : Int32)
    long_lived = [] of Process
    lock = Thread::Mutex.new
    failures = [] of String
    threads = [] of ProbeThread
    begin
      count.times do
        long_lived << Process.new(self_exe, ["--child", "sleep", "1300"], input: Process::Redirect::Pipe)
      end
      start = Time.instant
      count.times do |i|
        threads << ProbeThread.new("mixed-spawn-#{i}") do
          begin
            child = Process.new(self_exe, ["--child", "exit-code", ((i + 17) % 90).to_s])
            begin
              status = child.wait
              expected = (i + 17) % 90
              lock.synchronize { failures << "#{i}:#{status.exit_code?}:expected=#{expected}" unless status.exit_code? == expected }
            ensure
              child.close rescue nil
            end
          rescue ex
            lock.synchronize { failures << "#{i}:#{probe_failure_text(ex)}" }
          end
        end
      end
      threads.each(&.join)
      elapsed = Time.instant - start
      long_still_live = long_lived.count { |child| ProcessHandle.observe(child.pid).live? }
      {failures.empty? && long_still_live == count && elapsed < 1.second,
       details(count: count, immediate_failures: failures.join("|"), elapsed_ms: elapsed.total_milliseconds,
         long_still_live: long_still_live,
         contract: "concurrent short-lived exec/wait is not stalled by unrelated long-lived children and their inherited status resources")}
    ensure
      long_lived.each do |child|
        begin
          child.input.close rescue nil
        end
        cleanup(child)
      end
    end
  end

  def self.r9_kqueue_huge_timeout_case(seconds : Int64)
    child = Process.new(self_exe, ["--child", "delayed-exit-code", "120", "37"])
    reaped = false
    begin
      start = Time.instant
      result = with_kqueue do |kq|
        rc, _, errno = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS, EV_ADD | EV_ONESHOT)
        raise "registration failed: #{errno}" if rc < 0
        event_rc, event, event_errno = kevent_wait(kq, Time::Span.new(nanoseconds: seconds * 1_000_000_000_i64))
        {event_rc, event, event_errno}
      end
      elapsed = Time.instant - start
      status = child.wait
      reaped = true
      event_rc, event, event_errno = result
      {event_rc == 1 && (event.fflags & NOTE_EXIT) != 0 && status.exit_code? == 37 && elapsed < 2.seconds,
       details(timeout_seconds: seconds, event_rc: event_rc, event_errno: event_errno,
         fflags_hex: event.fflags.to_s(16), event_data: event.data, exit: status.exit_code?, elapsed_ms: elapsed.total_milliseconds)}
    ensure
      cleanup(child, reaped)
    end
  end

  def self.run_r9_source_matrix : Nil
    test("r9_concurrent_mixed_spawn_2") do
      r9_mixed_concurrent_spawn_case(2)
    end
    test("r9_concurrent_mixed_spawn_4") do
      r9_mixed_concurrent_spawn_case(4)
    end
    test("r9_concurrent_mixed_spawn_8") do
      r9_mixed_concurrent_spawn_case(8)
    end
    test("r9_concurrent_mixed_spawn_16") do
      r9_mixed_concurrent_spawn_case(16)
    end

    test("r9_direct_child_exit_precedes_inherited_pipe_eof") do
      marker = File.join(workdir, "r9-pipe-descendant-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "spawn-grandchild-and-exit", marker, "100"], output: Process::Redirect::Pipe)
      reaped = false
      reader_done = Atomic(Bool).new(false)
      reader_data = ""
      reader = nil.as(ProbeThread?)
      # Process#wait closes the child's pipes ("Waits for this process to complete and
      # closes any pipes"), so EOF can only be observed through an independent descriptor.
      output = IO::FileDescriptor.new(MacProbePosix.dup(child.output.fd))
      begin
        grandchild_pid = wait_file_value(marker).to_i64
        start = Time.instant
        status = child.wait
        reaped = true
        direct_elapsed = Time.instant - start
        reader = ProbeThread.new("pipe-reader") do
          reader_data = output.gets_to_end
          reader_done.set(true)
        end
        sleep 120.milliseconds
        held_open = !reader_done.get && ProcessHandle.observe(grandchild_pid).present?
        wait_until(3.seconds) { ProcessHandle.observe(grandchild_pid).state.dead? }
        eof_after_descendant = wait_until(2.seconds) { reader_done.get }
        reader.try(&.join)
        {status.success? && direct_elapsed < 600.milliseconds && held_open && eof_after_descendant,
         details(direct_exit_ms: direct_elapsed.total_milliseconds, grandchild_pid: grandchild_pid,
           pipe_held_open_after_direct_exit: held_open, eof_after_descendant: eof_after_descendant,
           bytes: reader_data.bytesize,
           contract: "direct child exit/reap is distinct from EOF when a descendant retains the inherited pipe")}
      ensure
        output.close rescue nil
        cleanup(child, reaped)
      end
    end

    test("r9_kqueue_exit_precedes_inherited_pipe_eof") do
      marker = File.join(workdir, "r9-kqueue-pipe-descendant-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "spawn-grandchild-and-exit", marker, "220"], output: Process::Redirect::Pipe)
      reaped = false
      reader_done = Atomic(Bool).new(false)
      reader = nil.as(ProbeThread?)
      output = IO::FileDescriptor.new(MacProbePosix.dup(child.output.fd)) # see note on Process#wait above
      begin
        grandchild_pid = wait_file_value(marker).to_i64
        result = with_kqueue do |kq|
          rc, _, errno = kevent_register(kq, child.pid, NOTE_EXIT, EV_ADD | EV_ONESHOT)
          raise "registration failed: #{errno}" if rc < 0
          kevent_wait(kq, 2.seconds)
        end
        reader = ProbeThread.new("kqueue-pipe-reader") do
          output.gets_to_end
          reader_done.set(true)
        end
        event_rc, event, event_errno = result
        sleep 100.milliseconds
        pipe_still_open = !reader_done.get && ProcessHandle.observe(grandchild_pid).present?
        status = child.wait; reaped = true
        wait_until(3.seconds) { ProcessHandle.observe(grandchild_pid).state.dead? }
        eof_after_descendant = wait_until(2.seconds) { reader_done.get }
        reader.try(&.join)
        {event_rc == 1 && (event.fflags & NOTE_EXIT) != 0 && status.success? && pipe_still_open && eof_after_descendant,
         details(event_rc: event_rc, event_errno: event_errno, fflags_hex: event.fflags.to_s(16),
           grandchild_pid: grandchild_pid, pipe_still_open: pipe_still_open, eof_after_descendant: eof_after_descendant,
           contract: "EVFILT_PROC child exit is independent of inherited-pipe EOF")}
      ensure
        output.close rescue nil
        cleanup(child, reaped)
      end
    end

    test("r13_group_signal_zombie_only_group_is_not_fatal") do
      # Darwin returns EPERM (not ESRCH, and not success as Linux does) from kill(-pgid, sig) once every
      # process left in the group is a zombie. Native evidence: explore/macos/signal_matrix.c.
      child, pgid, _ = spawn_group_child(3000, "zombie-only")
      group = ProcessSupervision.process_group(pgid)
      reaped = false
      begin
        group.kill
        gone = wait_until(2.seconds) { !ProcessHandle.observe(child.pid).state.live? }
        second = begin
          group.kill
          "returned"
        rescue ex
          probe_failure_text(ex)
        end
        empty_with_zombie = group.empty?
        status = child.wait
        reaped = true
        drained = group.wait_empty(1.second)
        {gone && second == "returned" && empty_with_zombie && drained,
         details(not_live_before_reap: gone, second_kill: second, empty_while_zombie: empty_with_zombie,
           drained_after_reap: drained, signal: status.exit_signal?,
           contract: "a group with no live member is empty and signalling it is a no-op, not an error")}
      ensure
        group.close
        cleanup(child, reaped)
      end
    end

    test("r9_kqueue_huge_timeout_86400s") do
      r9_kqueue_huge_timeout_case(86_400_i64)
    end
    test("r9_kqueue_huge_timeout_1000000s") do
      r9_kqueue_huge_timeout_case(1_000_000_i64)
    end
    test("r9_kqueue_huge_timeout_1000000000s") do
      r9_kqueue_huge_timeout_case(1_000_000_000_i64)
    end

    test("r9_concurrent_failed_spawn_fd_reuse_stress") do
      gc_settle
      baseline = fd_count_observation
      failures = Atomic(Int32).new(0)
      workers = Array(ProbeFiber).new(8) do |i|
        ProbeFiber.new("fd-stress-#{i}") do
          32.times do |j|
            reader, writer = IO.pipe
            begin
              begin
                Process.new(File.join(workdir, "missing-r9-#{i}-#{j}"), ["x"])
                failures.add(1)
              rescue File::NotFoundError | IO::Error
              end
              writer << "x"
              byte = reader.read_byte
              failures.add(1) unless byte == 'x'.ord
            ensure
              reader.close rescue nil
              writer.close rescue nil
            end
          end
        end
      end
      workers.each(&.join)
      after_no_gc = fd_count_observation
      gc_settle
      after = fd_count_observation
      delta = baseline >= 0 && after >= 0 ? after - baseline : 0
      {failures.get == 0 && (baseline < 0 || after < 0 || delta.abs <= 4),
       details(workers: workers.size, iterations_per_worker: 32, failures: failures.get,
         fd_before: baseline, fd_after: after, fd_delta: delta, fd_after_no_gc: after_no_gc,
         contract: "failed concurrent spawns do not close or reuse unrelated pipe descriptors")}
    end
  end

  def self.run : Nil
    Dir.mkdir_p(workdir)
    note("environment", details(crystal: Crystal::VERSION, os: "macos", pid: Process.pid, pgid: Process.pgid, executable: self_exe, workdir: workdir, pointer_bytes: sizeof(Void*)))

    test("darwin_proc_bsdinfo_static_size_and_observer") do
      sz = sizeof(MacProbeProc::BSDInfo)
      observed = ProcessHandle.observe(Process.pid)
      identity = observed.identity
      {sz == 136 && observed.state.live? && identity.try(&.generation_known?) == true,
       details(struct_size: sz, expected_size: 136, observer_state: observed.state,
         generation: identity.try(&.generation), note: "independent C ABI probe checks native header and raw proc_pidinfo")}
    end

    test("self_identity_and_state") do
      first = ProcessHandle.observe(Process.pid)
      second = ProcessHandle.observe(Process.pid)
      lookup = ProcessHandle.lookup(Process.pid)
      ok = first.state.live? && second.state.live? &&
           first.identity.try(&.generation_known?) == true &&
           first.identity.try(&.same_process?(second.identity.not_nil!)) == true &&
           lookup.try { |id| first.identity.try(&.same_process?(id)) } == true
      {ok, details(state: first.state, generation_known: first.identity.try(&.generation_known?),
        generation: first.identity.try(&.generation), second_generation: second.identity.try(&.generation),
        lookup_generation: lookup.try(&.generation))}
    end

    test("unsupported_stable_handle_not_fabricated") do
      outcome = "unexpected_open"
      begin
        h = ProcessHandle.current
        h.close
      rescue ex : ProcessHandle::Error::Unsupported
        outcome = "explicitly_unsupported"
      end
      {outcome == "explicitly_unsupported", details(result: outcome)}
    end

    test("invalid_pid_rejected") do
      outcome = "not_rejected"
      begin
        ProcessHandle.observe(0)
      rescue ArgumentError
        outcome = "argument_error"
      end
      {outcome == "argument_error", details(result: outcome)}
    end

    test("nonexistent_pid_observation") do
      pid = Int32::MAX
      obs = ProcessHandle.observe(pid)
      {obs.state.dead? || obs.state.unknown?, details(pid: pid, state: obs.state)}
    end

    test("child_creation_time_live_and_reaped") do
      child = child_sleep(900)
      reaped = false
      begin
        observed = ProcessHandle.observe(child.pid)
        looked_up = ProcessHandle.lookup(child.pid)
        snapshot_identity = observed.identity
        same = snapshot_identity.try { |id| looked_up.try { |other| id.same_process?(other) } }
        status = child.wait
        reaped = true
        dead = ProcessHandle.observe(child.pid)
        lookup_after = ProcessHandle.lookup(child.pid)
        {observed.state.live? && same == true && status.success? && dead.state.dead? && lookup_after.nil?,
         details(pid: child.pid, before: observed.state, after: dead.state, same_generation: same,
           before_token: snapshot_identity.try(&.generation), lookup_after: lookup_after.nil?, exit_code: status.exit_code)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("zombie_or_reaped_process_state_sampling") do
      child = child_sleep(130)
      reaped = false
      begin
        sleep 370.milliseconds
        before_wait = ProcessHandle.observe(child.pid)
        status = child.wait
        reaped = true
        after_wait = ProcessHandle.observe(child.pid)
        {status.success? && after_wait.state.dead?,
         details(pid: child.pid, before_wait: before_wait.state,
           after_wait: after_wait.state, exit_code: status.exit_code,
           note: "before_wait may be Zombie or Dead depending on Crystal child-reaper timing")}
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_child_exit_notification") do
      child = child_sleep(650)
      reaped = false
      begin
        info = await_exit_event(child.pid, 2.seconds)
        status = child.wait
        reaped = true
        ok = info["chg_rc"]? == "0" && info["event_rc"]? == "1" &&
             info["event_ident"]? == child.pid.to_s && info["note_exit"]? == "true" && status.success?
        {ok, info.merge(details(pid: child.pid, exit_code: status.exit_code))}
      ensure
        cleanup(child, reaped)
      end
    end

    test("kqueue_nonchild_registration_exploration") do
      marker = File.join(workdir, "mac-grandchild-#{Process.pid}.txt")
      intermediate = Process.new(self_exe, ["--child", "spawn-grandchild", marker])
      reaped = false
      begin
        raise "grandchild marker was not created" unless wait_for_file(marker)
        grandchild_pid = File.read(marker).strip.to_i64
        status = intermediate.wait
        reaped = true
        evidence = await_exit_event(grandchild_pid, 3.seconds)
        # Whether an unrelated/non-child PID can be registered is an observed
        # capability, not evidence of stable PID control or waitpid authority.
        observed_exit = evidence["chg_rc"]? == "0" && evidence["event_rc"]? == "1" &&
                        evidence["event_ident"]? == grandchild_pid.to_s &&
                        evidence["note_exit"]? == "true" && evidence["event_error"]? == "false"
        {status.success? && observed_exit, evidence.merge(details(grandchild_pid: grandchild_pid,
          intermediate_exit: status.exit_code, observed_exit: observed_exit,
          note: "observational capability probe, not a stable PID handle; support may vary by OS version"))}
      ensure
        cleanup(intermediate, reaped)
      end
    end

    test("process_group_targeted_terminate_and_drain") do
      marker = File.join(workdir, "group-terminate-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "group-sleep", "4000", marker])
      reaped = false
      group = nil.as(ProcessSupervision::Group?)
      begin
        ready = wait_for_file(marker)
        raise "group child did not publish readiness" unless ready
        fields = File.read(marker).split('|')
        pgid = fields[1].to_i64
        raise "test child not isolated from parent process group" if pgid != child.pid || pgid == Process.pgid
        raise "setpgid failed: #{fields}" if fields[2] != "0"
        group = ProcessSupervision.process_group(pgid)
        before = group.empty?
        timeout_result = group.wait_empty(40.milliseconds)
        group.terminate
        status = child.wait
        reaped = true
        drained = group.wait_empty(1.second)
        group.close
        signal = status.exit_signal?
        # A process terminated by SIGTERM has no normal exit code.  Avoid
        # Process::Status#exit_code, which raises on abnormal/signal exit.
        {(!before && !timeout_result && drained && group.closed? && signal == Signal::TERM && status.exit_code?.nil?),
         details(child_pid: child.pid, pgid: pgid, initially_empty: before, short_wait: timeout_result,
           drained: drained, signal_exit: status.signal_exit?, exit_signal: signal,
           exit_reason: status.exit_reason, status_code: status.exit_code?)}
      ensure
        group.try &.close
        cleanup(child, reaped)
      end
    end

    test("closing_posix_controller_does_not_kill_child") do
      marker = File.join(workdir, "group-close-#{Process.pid}.txt")
      child = Process.new(self_exe, ["--child", "group-sleep", "1600", marker])
      reaped = false
      begin
        raise "group child did not publish readiness" unless wait_for_file(marker)
        pgid = File.read(marker).split('|')[1].to_i64
        raise "unsafe group ID" if pgid != child.pid || pgid == Process.pgid
        group = ProcessSupervision.process_group(pgid)
        group.close
        state = ProcessHandle.observe(child.pid)
        # State is point-in-time, but the child should still be alive here.
        closed_operation = "not_rejected"
        begin
          group.empty?
        rescue ProcessSupervision::Error::Closed
          closed_operation = "closed_rejected"
        end
        child.terminate
        child.wait
        reaped = true
        {group.closed? && state.state.live? && closed_operation == "closed_rejected",
         details(child_pid: child.pid, state_after_controller_close: state.state, effect_after_close: closed_operation)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("standalone_spawn_argv_env_cwd") do
      marker = File.join(workdir, "mac-argv-#{Process.pid}.json")
      args = ["", "alpha beta", "a\"b", "back\\slash", "snowman-☃"]
      child = Process.new(self_exe, ["--child", "args", marker] + args, env: {"PROCESS_PROBE_TOKEN" => "mac-probe-0006"})
      reaped = false
      begin
        status = child.wait
        reaped = true
        payload = JSON.parse(File.read(marker))
        actual = payload["args"].as_a.map(&.as_s)
        {status.success? && actual == args && payload["probe_env"].as_s == "mac-probe-0006",
         details(exit_code: status.exit_code, args_exact: actual == args, env_exact: payload["probe_env"].as_s == "mac-probe-0006", child_cwd: payload["cwd"].as_s)}
      ensure
        cleanup(child, reaped)
      end
    end

    test("r7_crystal_runtime_default_sigpipe_is_ignored") do
      child = Process.new(self_exe, ["--child", "self-signal-runtime-default", "30", Signal::PIPE.value.to_s])
      reaped = false
      begin
        status = child.wait
        reaped = true
        {status.exit_code? == 93 && status.exit_signal?.nil?,
         details(exit_code: status.exit_code?, exit_signal: status.exit_signal?, raw: status.system_exit_status,
           contract: "Crystal runtime ignores SIGPIPE unless explicitly reset")}
      ensure
        cleanup(child, reaped)
      end
    end

    test("r7_kqueue_runtime_default_sigpipe_then_normal_exit") do
      child = Process.new(self_exe, ["--child", "self-signal-runtime-default", "80", Signal::PIPE.value.to_s])
      reaped = false
      begin
        result = with_kqueue do |kq|
          reg_rc, _, reg_errno = kevent_register(kq, child.pid, NOTE_EXIT | NOTE_EXITSTATUS)
          event_rc, event, event_errno = kevent_next(kq, 2.seconds)
          status = child.wait
          reaped = true
          ok = reg_rc == 0 && event_rc == 1 && (event.fflags & NOTE_EXIT) != 0 &&
               status.exit_code? == 93 && status.exit_signal?.nil? && event.data.to_u32 == status.system_exit_status
          {ok, decode_kevent(event).merge(details(exit_code: status.exit_code?, exit_signal: status.exit_signal?,
            reg_errno: reg_errno, event_errno: event_errno, contract: "ignored SIGPIPE followed by normal exit"))}
        end
        result
      ensure
        cleanup(child, reaped)
      end
    end

    test("r8_native_c_zombie_holder_produces_signal_visible_unreaped_child") do
      marker = File.join(workdir, "r8-native-zombie-control-#{Process.pid}.txt")
      holder = spawn_native_zombie_holder(marker, 40)
      reaped = false
      begin
        zombie_pid = wait_file_value(marker).to_i64
        signal_present = wait_until(700.milliseconds) { pid_present_by_signal?(zombie_pid) }
        status = holder.wait
        reaped = true
        dead_after = ProcessHandle.observe(zombie_pid).state.dead?
        {signal_present && status.success? && dead_after,
         details(signal_present: signal_present, holder_exit: status.exit_code?, dead_after: dead_after,
           contract: "native helper, not Crystal, owns and temporarily leaves the target child unreaped")}
      ensure
        cleanup(holder, reaped)
      end
    end

    test("r7_unreaped_zombie_presence_is_not_false_dead") do
      marker = File.join(workdir, "r7-zombie-presence-#{Process.pid}.txt")
      holder = spawn_native_zombie_holder(marker, 41)
      reaped = false
      begin
        zombie_pid = wait_file_value(marker).to_i64
        obs = wait_for_observation(zombie_pid, 700.milliseconds) { |o| !o.state.live? }
        signal_present = pid_present_by_signal?(zombie_pid)
        status = holder.wait
        reaped = true
        after = ProcessHandle.observe(zombie_pid)
        {signal_present && !obs.state.dead? && (obs.state.zombie? || obs.state.unknown?) && status.success? && after.state.dead?,
         details(state: obs.state, signal_present: signal_present, identity_present: !obs.identity.nil?, after: after.state)}
      ensure
        cleanup(holder, reaped)
      end
    end

    test("r7_kinfo_fallback_recovers_unreaped_zombie_and_generation") do
      marker = File.join(workdir, "r7-kinfo-zombie-#{Process.pid}.txt")
      holder = spawn_native_zombie_holder(marker, 42)
      reaped = false
      begin
        zombie_pid = wait_file_value(marker).to_i64
        obs = wait_for_observation(zombie_pid, 700.milliseconds) { |o| o.state.zombie? }
        identity = ProcessHandle.lookup(zombie_pid)
        status = holder.wait
        reaped = true
        after = ProcessHandle.observe(zombie_pid)
        {obs.state.zombie? && obs.identity.try(&.generation_known?) == true &&
          identity.try(&.generation_known?) == true && obs.identity.try(&.same_process?(identity.not_nil!)) == true &&
          status.success? && after.state.dead?,
         details(state: obs.state, observation_generation: obs.identity.try(&.generation),
           lookup_generation: identity.try(&.generation), after: after.state,
           contract: "runtime-validated KERN_PROC_PID fallback recovers libproc-hidden zombie identity")}
      ensure
        cleanup(holder, reaped)
      end
    end

    run_expanded
    run_identity_exhaustive
    run_kqueue_exhaustive
    run_group_exhaustive
    run_spawn_exhaustive
    run_deep_native_matrix
    run_completion_matrix
    run_r6_matrix
    run_r9_source_matrix
  ensure
    finish
  end
end

if ARGV[0]? == "--child"
  NativeProbe.child_mode
else
  NativeProbe.run
end
