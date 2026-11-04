# Spawning from Crystal without Process.new, and handing the pid back to Process. Records JSON lines, never asserts.
#
# Facts from the 1.21.1 stdlib source that this checks on the runners:
#  * Crystal traps SIGCHLD and its handler calls waitpid(-1, WNOHANG): it reaps EVERY child of the process and keeps
#    the status of pids nobody has asked about yet in a table (@@pending), handing it over when
#    Crystal::System::Process.new(pid) registers. So a pid made by posix_spawn / clone3 needs no reaper of its own,
#    and may be wrapped after it already exited.
#  * Process.new(Crystal::System::Process) is a public (:nodoc) constructor; the kit's Windows spawn uses it.
#  * The stdlib wraps fork in Crystal::System::Process.lock_write (keeps descriptors made by other threads away from the
#    child on Darwin, which lacks pipe2/accept4) and blocks every signal around it.
#
# Cases: wrapping a posix_spawn child; wrapping after it exited; an own waitpid racing the runtime; the child's view
# under SETPGROUP|SETSIGDEF|SETSIGMASK compared with Process.run; macOS START_SUSPENDED; concurrent spawners; spawn cost
# with a small and a 512 MiB heap against Process.run (fork); and on Linux the same through a raw
# clone3(CLONE_INTO_CGROUP) (needs a delegated cgroup directory).
#
# Build: crystal build explore/posix/crystal_own_spawn.cr -o crystal_own_spawn   (also with -Dpreview_mt -Dexecution_context)
# Run:   ./crystal_own_spawn <spawn_attrs binary> [delegated cgroup dir]
require "json"

PROBE = "crystal_own_spawn"

lib LibOwn
  fun posix_spawn(pid : Int32*, path : UInt8*, file_actions : Void*, attrp : Void*, argv : UInt8**, envp : UInt8**) : Int32
  fun posix_spawnattr_init(attr : Void*) : Int32
  fun posix_spawnattr_destroy(attr : Void*) : Int32
  fun posix_spawnattr_setflags(attr : Void*, flags : Int16) : Int32
  fun posix_spawnattr_setpgroup(attr : Void*, pgroup : Int32) : Int32
  fun posix_spawnattr_setsigdefault(attr : Void*, sigs : Void*) : Int32
  fun posix_spawnattr_setsigmask(attr : Void*, sigs : Void*) : Int32
  fun posix_spawn_file_actions_init(fa : Void*) : Int32
  fun posix_spawn_file_actions_destroy(fa : Void*) : Int32
  fun posix_spawn_file_actions_adddup2(fa : Void*, fd : Int32, newfd : Int32) : Int32
end

def emit(kase : String, &)
  line = JSON.build do |j|
    j.object do
      j.field "probe", PROBE
      j.field "case", kase
      begin
        yield j
      rescue ex
        j.field "unhandled_error", "#{ex.class}: #{ex.message}"
      end
    end
  end
  puts line
  STDOUT.flush
end

# NUL-terminated C string array whose strings stay alive as long as this object does
class CStrings
  @strs : Array(String)
  getter ptrs : Pointer(Pointer(UInt8))

  def initialize(list : Array(String))
    @strs = list.map(&.dup)
    @ptrs = Pointer(Pointer(UInt8)).malloc(list.size + 1)
    @strs.each_with_index { |s, i| @ptrs[i] = s.to_unsafe }
    @ptrs[list.size] = Pointer(UInt8).null
  end
end

def current_env : CStrings
  list = [] of String
  ENV.each { |k, v| list << "#{k}=#{v}" }
  CStrings.new(list)
end

# posix_spawn with the attributes a supervisor wants; returns {rc, pid}
def own_spawn(path : String, args : Array(String), *, pgroup = false, sigreset = false, suspended = false, out_fd : Int32? = nil) : {Int32, Int32}
  attr = StaticArray(UInt8, 512).new(0_u8)
  fa = StaticArray(UInt8, 512).new(0_u8)
  all = StaticArray(UInt8, 256).new(0_u8)
  none = StaticArray(UInt8, 256).new(0_u8)
  LibOwn.posix_spawnattr_init(pointerof(attr))
  LibOwn.posix_spawn_file_actions_init(pointerof(fa))
  flags = 0_i16
  if pgroup
    flags |= 0x02_i16 # POSIX_SPAWN_SETPGROUP
    LibOwn.posix_spawnattr_setpgroup(pointerof(attr), 0)
  end
  if sigreset
    LibC.sigfillset(pointerof(all).as(LibC::SigsetT*))
    LibC.sigemptyset(pointerof(none).as(LibC::SigsetT*))
    LibOwn.posix_spawnattr_setsigdefault(pointerof(attr), pointerof(all))
    LibOwn.posix_spawnattr_setsigmask(pointerof(attr), pointerof(none))
    flags |= 0x04_i16 | 0x08_i16 # SETSIGDEF | SETSIGMASK
  end
  {% if flag?(:darwin) %}
    flags |= 0x80_i16 if suspended # POSIX_SPAWN_START_SUSPENDED
  {% end %}
  LibOwn.posix_spawnattr_setflags(pointerof(attr), flags)
  if fd = out_fd
    LibOwn.posix_spawn_file_actions_adddup2(pointerof(fa), fd, 1)
  end
  argv = CStrings.new([path] + args)
  envp = current_env
  pid = 0_i32
  rc = Crystal::System::Process.lock_write do
    LibOwn.posix_spawn(pointerof(pid), path, pointerof(fa), pointerof(attr), argv.ptrs, envp.ptrs)
  end
  LibOwn.posix_spawnattr_destroy(pointerof(attr))
  LibOwn.posix_spawn_file_actions_destroy(pointerof(fa))
  {rc, pid}
end

def wrap(pid : Int32) : Process
  Process.new(Crystal::System::Process.new(pid))
end

# wait with a deadline; nil on timeout
def wait_within(process : Process, span : Time::Span) : Process::Status?
  ch = Channel(Process::Status).new(1)
  spawn { ch.send(process.wait) }
  select
  when st = ch.receive
    st
  when timeout(span)
    nil
  end
end

def status_text(st : Process::Status?) : String
  return "timeout" unless st
  st.normal_exit? ? "exited(#{st.exit_code})" : "signaled(#{st.exit_signal? || st.system_exit_status})"
end

def median(a : Array(Float64)) : Float64
  s = a.sort
  s.empty? ? -1.0 : s[s.size // 2]
end

def zombie_children : Int32
  me = Process.pid
  n = 0
  Dir.each_child("/proc") do |d|
    next unless d[0]?.try(&.ascii_number?)
    begin
      stat = File.read("/proc/#{d}/stat")
    rescue
      next
    end
    rp = stat.rindex(')')
    next unless rp
    fields = stat[(rp + 2)..].split(' ')
    n += 1 if fields[0]? == "Z" && fields[1]?.try(&.to_i?) == me
  end
  n
rescue
  -1
end

{% if flag?(:linux) %}
  def clone3_spawn(dirfd : Int32, path : String, args : Array(String), out_fd : Int32) : Int32
    argv = CStrings.new([path] + args)
    envp = current_env
    ca = StaticArray(UInt64, 11).new(0_u64)
    ca[0] = 0x200000000_u64 # CLONE_INTO_CGROUP
    ca[4] = 17_u64          # exit_signal = SIGCHLD
    ca[10] = dirfd.to_u64
    blocked = uninitialized LibC::SigsetT
    old = uninitialized LibC::SigsetT
    empty = uninitialized LibC::SigsetT
    LibC.sigfillset(pointerof(blocked))
    LibC.sigemptyset(pointerof(empty))
    LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(blocked), pointerof(old))
    pid = Crystal::System::Process.lock_write do
      LibC.syscall(435_i64, pointerof(ca), 88_u64)
    end
    if pid == 0
      # the child: system calls only, no allocation, no runtime
      LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(empty), nil)
      LibC.dup2(out_fd, 1)
      LibC.execve(path, argv.ptrs, envp.ptrs)
      LibC._exit(127)
    end
    e = Errno.value
    LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(old), nil)
    raise "clone3 failed: #{e}" if pid < 0
    pid.to_i32
  end

{% end %}

# a hung case must not hold the CI job: this fiber ends the probe (it cannot run while a blocking waitpid holds the thread)
spawn do
  sleep 280.seconds
  puts %({"probe":"#{PROBE}","case":"_watchdog","note":"stopped after 280 s"})
  STDOUT.flush
  exit 3
end

report_bin = ARGV[0]? || abort("usage: crystal_own_spawn <spawn_attrs binary> [cgroup dir]")
cgroup_dir = ARGV[1]?

emit("_platform") do |j|
  j.field "crystal", Crystal::VERSION
  j.field "target", Crystal::DESCRIPTION.lines.first? || ""
  j.field "preview_mt", {{ flag?(:preview_mt) }}
  j.field "execution_context", {{ flag?(:execution_context) }}
end

# --- cost of a spawn against the size of this process's heap (run once per size, each in a fresh process:
#     OWN_SPAWN_BENCH_MIB=256 ./crystal_own_spawn <spawn_attrs> [cgroup dir]) --------------------------------------------
TRUE_BIN = File.exists?("/bin/true") ? "/bin/true" : "/usr/bin/true"

if mib_s = ENV["OWN_SPAWN_BENCH_MIB"]?
  mib = mib_s.to_i
  big = mib > 0 ? Bytes.new(mib.to_i64 * 1024 * 1024, 0xA5_u8) : Bytes.empty
  emit("spawn_cost_heap_#{mib}_MiB") do |j|
    n = 25
    stdlib_call = [] of Float64
    stdlib_total = [] of Float64
    own_call = [] of Float64
    own_total = [] of Float64
    n.times do
      t0 = Time.instant
      p = Process.new(TRUE_BIN)
      stdlib_call << t0.elapsed.total_milliseconds
      p.wait
      stdlib_total << t0.elapsed.total_milliseconds
      t1 = Time.instant
      rc, pid = own_spawn(TRUE_BIN, [] of String)
      own_call << t1.elapsed.total_milliseconds
      wait_within(wrap(pid), 5.seconds)
      own_total << t1.elapsed.total_milliseconds
    end
    j.field "Process.new_call_ms", median(stdlib_call)
    j.field "Process.new_until_waited_ms", median(stdlib_total)
    j.field "posix_spawn_call_ms", median(own_call)
    j.field "posix_spawn_until_waited_ms", median(own_total)
    {% if flag?(:linux) %}
      if dir = cgroup_dir
        leaf = File.join(dir, "crystal-bench")
        Dir.mkdir(leaf) unless Dir.exists?(leaf)
        dirfd = LibC.open(leaf, LibC::O_RDONLY | LibC::O_CLOEXEC)
        calls = [] of Float64
        totals = [] of Float64
        n.times do
          r, w = IO.pipe(write_blocking: true)
          t0 = Time.instant
          pid = clone3_spawn(dirfd, TRUE_BIN, [] of String, w.fd)
          calls << t0.elapsed.total_milliseconds
          w.close
          wait_within(wrap(pid), 5.seconds)
          totals << t0.elapsed.total_milliseconds
          r.close
        end
        j.field "clone3_call_ms", median(calls)
        j.field "clone3_until_waited_ms", median(totals)
        LibC.close(dirfd)
        File.write(File.join(leaf, "cgroup.kill"), "1") rescue nil
        sleep 50.milliseconds
        Dir.delete(leaf) rescue nil
      end
    {% end %}
  end
  big[0] = 1_u8 if mib > 0
  exit 0
end


# --- wrapping ------------------------------------------------------------------------------------------------------
emit("posix_spawn_then_wrap_and_wait") do |j|
  rc, pid = own_spawn("/bin/sh", ["-c", "sleep 0.1; exit 7"])
  j.field "posix_spawn_rc", rc
  p = wrap(pid)
  st = wait_within(p, 5.seconds)
  j.field "status", status_text(st)
  j.field "wait_returned_before_deadline", !st.nil?
end

emit("child_exits_before_wrap_status_is_kept") do |j|
  rc, pid = own_spawn("/bin/sh", ["-c", "exit 9"])
  sleep 300.milliseconds
  gone = LibC.kill(pid, 0) != 0 # reaped by the runtime's SIGCHLD loop already?
  j.field "posix_spawn_rc", rc
  j.field "pid_already_gone_before_wrap", gone
  j.field "zombies_of_this_process", zombie_children
  st = wait_within(wrap(pid), 3.seconds)
  j.field "status_from_wrap_after_exit", status_text(st)
end

emit("own_waitpid_wins_then_wrap_hangs") do |j|
  rc, pid = own_spawn("/bin/sh", ["-c", "exit 3"])
  # a blocking waitpid on this thread: the SIGCHLD fiber cannot run meanwhile, so this call reaps the child
  r = LibC.waitpid(pid, out status, 0)
  j.field "own_waitpid_rc_is_pid", r == pid
  j.field "own_waitpid_exit_code", (status >> 8) & 0xff
  st = wait_within(wrap(pid), 1500.milliseconds)
  j.field "wrap_wait_after_own_reap", status_text(st)
end

emit("own_waitpid_after_runtime_reaped") do |j|
  rc, pid = own_spawn("/bin/sh", ["-c", "exit 4"])
  sleep 300.milliseconds
  r = LibC.waitpid(pid, out status, LibC::WNOHANG)
  j.field "own_waitpid_rc", r
  j.field "errno", r < 0 ? Errno.value.to_s : "none"
end

# --- what the child sees --------------------------------------------------------------------------------------------
Signal::HUP.ignore

def child_view_stdlib(bin : String) : String
  io = IO::Memory.new
  Process.run(bin, ["--report"], output: io, error: Process::Redirect::Close)
  io.to_s.strip
end

def child_view_own(bin : String, **opts) : String
  r, w = IO.pipe(write_blocking: true)
  rc, pid = own_spawn(bin, ["--report"], **opts, out_fd: w.fd)
  w.close
  text = r.gets_to_end.strip
  r.close
  wait_within(wrap(pid), 3.seconds)
  text
end

emit("child_view_stdlib_process_run") do |j|
  j.field "report", JSON.parse(child_view_stdlib(report_bin))
end
emit("child_view_own_spawn_plain") do |j|
  j.field "report", JSON.parse(child_view_own(report_bin))
end
emit("child_view_own_spawn_pgroup_and_sigreset") do |j|
  j.field "report", JSON.parse(child_view_own(report_bin, pgroup: true, sigreset: true))
end

{% if flag?(:darwin) %}
  emit("start_suspended_wrap_resume") do |j|
    r, w = IO.pipe(write_blocking: true)
    rc, pid = own_spawn(report_bin, ["--report"], pgroup: true, suspended: true, out_fd: w.fd)
    w.close
    j.field "posix_spawn_rc", rc
    p = wrap(pid)
    # gets_to_end returns at EOF, i.e. when the child has printed and exited
    ch = Channel(Int32).new(1)
    spawn { ch.send(r.gets_to_end.bytesize) }
    ran_while_suspended = false
    total = -1
    select
    when n = ch.receive
      ran_while_suspended = true
      total = n
    when timeout(300.milliseconds)
    end
    j.field "child_ran_while_suspended", ran_while_suspended
    j.field "child_in_own_pgroup_right_after_spawn", LibC.getpgid(pid) == pid
    LibC.kill(pid, Signal::CONT.value)
    total = ch.receive unless ran_while_suspended
    j.field "output_bytes_after_SIGCONT", total
    j.field "status", status_text(wait_within(p, 3.seconds))
    r.close
  end

  emit("start_suspended_kill_then_wrap") do |j|
    rc, pid = own_spawn("/bin/sleep", ["30"], pgroup: true, suspended: true)
    p = wrap(pid)
    LibC.kill(pid, Signal::KILL.value)
    j.field "status", status_text(wait_within(p, 3.seconds))
  end
{% end %}

# --- concurrency and cost -------------------------------------------------------------------------------------------
emit("concurrent_spawners") do |j|
  fibers = 4
  per = 25
  done = Channel({Int32, Int32}).new(fibers)
  fibers.times do
    spawn do
      ok = 0
      bad = 0
      per.times do
        rc, pid = own_spawn("/bin/sh", ["-c", "exit 5"])
        if rc != 0
          bad += 1
          next
        end
        st = wait_within(wrap(pid), 5.seconds)
        if st && st.exit_code == 5
          ok += 1
        else
          bad += 1
        end
      end
      done.send({ok, bad})
    end
  end
  ok = 0
  bad = 0
  fibers.times do
    a, b = done.receive
    ok += a
    bad += b
  end
  j.field "spawns", fibers * per
  j.field "correct_status", ok
  j.field "wrong_or_missing", bad
  j.field "zombies_afterwards", zombie_children
end


# --- Linux: clone3(CLONE_INTO_CGROUP) from Crystal ------------------------------------------------------------------
{% if flag?(:linux) %}
  if dir = cgroup_dir
    leaf = File.join(dir, "crystal-clone3")
    Dir.mkdir(leaf) unless Dir.exists?(leaf)
    dirfd = LibC.open(leaf, LibC::O_RDONLY | LibC::O_CLOEXEC) # a directory opened read-only is enough for clone3
    rel = leaf.sub("/sys/fs/cgroup", "")

    emit("clone3_into_cgroup_wrap_and_read") do |j|
      r, w = IO.pipe(write_blocking: true)
      pid = clone3_spawn(dirfd, "/bin/cat", ["/proc/self/cgroup"], w.fd)
      w.close
      p = wrap(pid)
      seen = r.gets_to_end.strip
      r.close
      j.field "child_saw_cgroup", seen
      j.field "expected", "0::#{rel}"
      j.field "child_in_target", seen == "0::#{rel}"
      j.field "status", status_text(wait_within(p, 3.seconds))
    end

    emit("clone3_child_exits_before_wrap") do |j|
      r, w = IO.pipe(write_blocking: true)
      pid = clone3_spawn(dirfd, "/bin/sh", ["-c", "exit 6"], w.fd)
      w.close
      sleep 300.milliseconds
      j.field "pid_gone_before_wrap", LibC.kill(pid, 0) != 0
      j.field "status", status_text(wait_within(wrap(pid), 3.seconds))
      r.close
    end

    emit("clone3_many_spawns") do |j|
      ok = 0
      n = 100
      n.times do
        r, w = IO.pipe(write_blocking: true)
        pid = clone3_spawn(dirfd, "/bin/sh", ["-c", "exit 0"], w.fd)
        w.close
        st = wait_within(wrap(pid), 5.seconds)
        ok += 1 if st && st.exit_code == 0
        r.close
      end
      j.field "spawns", n
      j.field "exit_0", ok
      j.field "zombies_afterwards", zombie_children
    end

    LibC.close(dirfd)
    File.write(File.join(leaf, "cgroup.kill"), "1") rescue nil
    sleep 50.milliseconds
    Dir.delete(leaf) rescue nil
  end
{% end %}
