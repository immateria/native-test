# Windows native process qualification harness for Crystal Process Development 0009, probe revision 12.
# Compile with Crystal 1.21.1+. All destructive operations target owned children
# and newly created unnamed Job Objects; never use with elevation.
require "json"
require "process-supervision"

{% unless flag?(:win32) %}
  {% raise "windows_process_probe.cr must be compiled for Windows" %}
{% end %}

@[Link("kernel32")]
lib WindowsProbeNative
  fun GetCurrentProcess : LibC::HANDLE
  fun IsProcessInJob(process : LibC::HANDLE, job : LibC::HANDLE, result : LibC::BOOL*) : LibC::BOOL
  fun GetProcessId(process : LibC::HANDLE) : UInt32
  fun GetProcessHandleCount(process : LibC::HANDLE, count : UInt32*) : LibC::BOOL
  fun GetHandleInformation(handle : LibC::HANDLE, flags : UInt32*) : LibC::BOOL
  fun SetHandleInformation(handle : LibC::HANDLE, mask : UInt32, flags : UInt32) : LibC::BOOL
  fun CreateEventW(security : LibC::SECURITY_ATTRIBUTES*, manual_reset : LibC::BOOL,
                   initial : LibC::BOOL, name : UInt16*) : LibC::HANDLE
end

# Additional probe-only Win32 declarations used to exercise native behavior
# adjacent to the public shards. These declarations never ship in the shards.
@[Link("kernel32")]
@[Link("advapi32")]
lib WindowsProbeExtra
  struct JobNotificationLimit
    io_read_bytes_limit : UInt64
    io_write_bytes_limit : UInt64
    per_job_user_time_limit : Int64
    job_memory_limit : UInt64
    rate_control_tolerance : Int32
    rate_control_tolerance_interval : Int32
    limit_flags : UInt32
  end

  struct JobLimitViolation
    limit_flags : UInt32
    violation_limit_flags : UInt32
    io_read_bytes : UInt64
    io_read_bytes_limit : UInt64
    io_write_bytes : UInt64
    io_write_bytes_limit : UInt64
    per_job_user_time : Int64
    per_job_user_time_limit : Int64
    job_memory : UInt64
    job_memory_limit : UInt64
    rate_control_tolerance : Int32
    rate_control_tolerance_limit : Int32
  end

  fun QueryInformationJobObject(job : LibC::HANDLE, info_class : UInt32, info : Void*, length : UInt32, return_length : UInt32*) : LibC::BOOL
  fun OpenProcessToken(process : LibC::HANDLE, access : UInt32, token : LibC::HANDLE*) : LibC::BOOL
  fun GetTokenInformation(token : LibC::HANDLE, info_class : UInt32, info : Void*, length : UInt32, return_length : UInt32*) : LibC::BOOL
  fun LookupPrivilegeNameW(system_name : UInt16*, luid : UInt64*, name : UInt16*, length : UInt32*) : LibC::BOOL
  fun GetPriorityClass(process : LibC::HANDLE) : UInt32
  fun GetProcessAffinityMask(process : LibC::HANDLE, process_mask : LibC::DWORD_PTR*, system_mask : LibC::DWORD_PTR*) : LibC::BOOL
  fun ExitProcess(code : UInt32) : NoReturn
  fun SetStdHandle(kind : UInt32, handle : LibC::HANDLE) : LibC::BOOL
end

# Probe-only white-box hooks. They are compiled only into this qualification
# executable and never into either shard artifact.
private module ProcessHandle::Windows::Native
  @@probe_fail_unregister = Atomic(Bool).new(false)

  def self.probe_fail_unregister=(value : Bool) : Bool
    @@probe_fail_unregister.set(value)
    value
  end

  def self.unregister_wait_blocking(wait_handle : LibC::HANDLE) : Nil
    if @@probe_fail_unregister.swap(false)
      raise ProcessHandle::Error::Native.new("UnregisterWaitEx", "injected probe failure")
    end
    previous_def
  end
end

class ProcessHandle::Windows
  @@probe_spawn_identity_mismatch_once = Atomic(Bool).new(false)
  @@probe_spawn_close_failure_once = Atomic(Bool).new(false)

  def self.probe_arm_spawn_cleanup_double_failure : Nil
    @@probe_spawn_identity_mismatch_once.set(true)
    @@probe_spawn_close_failure_once.set(true)
  end

  def self.probe_clear_spawn_cleanup_faults : Nil
    @@probe_spawn_identity_mismatch_once.set(false)
    @@probe_spawn_close_failure_once.set(false)
  end

  def identity : ProcessHandle::Identity
    current = @identity
    if @@probe_spawn_identity_mismatch_once.swap(false)
      generation = current.generation || 0_u64
      return ProcessHandle::Identity.new(current.pid, generation &+ 1_u64)
    end
    current
  end

  def close : Nil
    if @@probe_spawn_close_failure_once.swap(false)
      raise ProcessHandle::Error::Native.new("CloseHandle(process)", "injected spawn-cleanup close failure")
    end
    previous_def
  end

  def probe_native_handle_address : UInt64
    @mutex.synchronize { checked_handle.address.to_u64 }
  end

  def probe_is_in_job(job_handle : LibC::HANDLE) : Bool
    @mutex.synchronize do
      answer = LibC::BOOL.new(0)
      rc = WindowsProbeNative.IsProcessInJob(checked_handle, job_handle, pointerof(answer))
      raise "IsProcessInJob failed: #{LibC.GetLastError}" if rc == 0
      answer != 0
    end
  end

  def probe_force_native_close_without_publish : Nil
    @mutex.synchronize { Native.close_native_handle(checked_handle) }
  end

  def probe_registered_wait_unregister_failure(timeout : Time::Span) : String
    duplicate = @mutex.synchronize { Native.duplicate(checked_handle) }
    begin
      Native.probe_fail_unregister = true
      FiberWait.probe_unregister_failure(duplicate, timeout)
    ensure
      Native.probe_fail_unregister = false
      Native.close_native_handle(duplicate)
    end
  end

  def probe_registered_wait_wake_failure(timeout : Time::Span) : String
    duplicate = @mutex.synchronize { Native.duplicate(checked_handle) }
    begin
      FiberWait.probe_wake_failure(duplicate, timeout)
    ensure
      Native.close_native_handle(duplicate)
    end
  end

  private class FiberWait
    def self.probe_unregister_failure(process_handle : LibC::HANDLE, timeout : Time::Span) : String
      # Inject the cleanup error before the real unregister API is called. This
      # exercises the production exceptional lifetime path without double-using
      # an already unregistered opaque wait registration. The helper process is
      # isolated and exits immediately after recording the result.
      instance = new(process_handle, Native.registered_wait_milliseconds(timeout))
      begin
        instance.wait
        "unexpected_success"
      rescue ex
        "#{ex.class.name}:#{ex.message}"
      end
    end

    def self.probe_wake_failure(process_handle : LibC::HANDLE, timeout : Time::Span) : String
      instance = new(process_handle, Native.registered_wait_milliseconds(timeout))
      instance.probe_close_writer
      begin
        instance.wait
        "unexpected_success"
      rescue ex
        "#{ex.class.name}:#{ex.message}"
      end
    end

    def probe_close_writer : Nil
      @context.value.close_write_handle unless @context.null?
    end
  end
end

module ProcessSupervision::Windows
  class Job
    def probe_native_handle : LibC::HANDLE
      @mutex.synchronize { checked_handle }
    end

    def probe_force_native_job_close_without_publish : Nil
      @mutex.synchronize { Native.close_native_handle(checked_handle) }
    end

    def probe_force_event_port_closed_before_stop : Nil
      reader = @mutex.synchronize { @events }
      reader.try &.probe_force_port_close
    end

    def probe_force_event_port_closed_after_stop : Nil
      reader = @mutex.synchronize { @events }
      reader.try &.probe_stop_then_force_port_close
    end

    private class EventReader
      def probe_force_port_close : Nil
        @close_lock.synchronize { Native.close_native_handle(@port) unless @port.null? }
      end

      def probe_stop_then_force_port_close : Nil
        @close_lock.synchronize do
          unless @stopped
            if LibC.PostQueuedCompletionStatus(@port, 0, STOP_KEY, Pointer(LibC::OVERLAPPED).null) == 0
              raise Native.error("PostQueuedCompletionStatus(Job event stop probe)")
            end
            until @reader_stopped.get
              Thread.sleep(1.millisecond)
            end
            @stopped = true
          end
          Native.close_native_handle(@port) unless @port.null?
        end
      end
    end
  end
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

  private JOB_OBJECT_LIMIT_WORKINGSET                 = 0x00000001_u32
  private JOB_OBJECT_LIMIT_PROCESS_TIME               = 0x00000002_u32
  private JOB_OBJECT_LIMIT_JOB_TIME                   = 0x00000004_u32
  private JOB_OBJECT_LIMIT_ACTIVE_PROCESS             = 0x00000008_u32
  private JOB_OBJECT_LIMIT_AFFINITY                   = 0x00000010_u32
  private JOB_OBJECT_LIMIT_PRIORITY_CLASS             = 0x00000020_u32
  private JOB_OBJECT_LIMIT_SCHEDULING_CLASS           = 0x00000080_u32
  private JOB_OBJECT_LIMIT_PROCESS_MEMORY             = 0x00000100_u32
  private JOB_OBJECT_LIMIT_JOB_MEMORY                 = 0x00000200_u32
  private JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400_u32
  private JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK        = 0x00001000_u32
  private JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          = 0x00002000_u32
  private JOB_OBJECT_LIMIT_BREAKAWAY_OK               = 0x00000800_u32
  private CPU_RATE_ENABLE                             = 0x00000001_u32
  private CPU_RATE_HARD_CAP                           = 0x00000004_u32
  private JOB_OBJECT_MSG_NEW_PROCESS                  =          6_u32
  private JOB_OBJECT_MSG_EXIT_PROCESS                 =          7_u32
  private JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO          =          4_u32
  private JOB_BASIC_PROCESS_ID_LIST_CLASS             =          3_u32
  private JOB_END_OF_JOB_TIME_CLASS                   =          6_u32
  private JOB_ASSOCIATE_COMPLETION_PORT_CLASS         =          7_u32
  private JOB_EXTENDED_LIMIT_CLASS                    =          9_u32
  private JOB_NOTIFICATION_LIMIT_CLASS                =         12_u32
  private JOB_LIMIT_VIOLATION_CLASS                   =         13_u32
  private JOB_OBJECT_MSG_NOTIFICATION_LIMIT           =         11_u32
  private JOB_OBJECT_LIMIT_JOB_READ_BYTES             = 0x00010000_u32
  private JOB_OBJECT_LIMIT_JOB_WRITE_BYTES            = 0x00020000_u32
  private JOB_BASIC_UI_RESTRICTIONS_CLASS             =          4_u32
  private JOB_CPU_RATE_CONTROL_CLASS                  =         15_u32
  private STILL_ACTIVE                                =        259_u32
  private CREATE_BREAKAWAY_FROM_JOB                   = 0x01000000_u32
  private INVALID_HANDLE_VALUE                        = LibC::HANDLE.new(UInt64::MAX)
  private ERROR_PRIVILEGE_NOT_HELD                    = 1314_u32
  private HANDLE_FLAG_INHERIT                         =    1_u32

  def self.current_handle_count : UInt32
    count = 0_u32
    rc = WindowsProbeNative.GetProcessHandleCount(WindowsProbeNative.GetCurrentProcess, pointerof(count))
    raise "GetProcessHandleCount failed: #{LibC.GetLastError}" if rc == 0
    count
  end

  def self.parent_in_job? : Bool
    in_job = LibC::BOOL.new(0)
    rc = WindowsProbeNative.IsProcessInJob(WindowsProbeNative.GetCurrentProcess, LibC::HANDLE.null, pointerof(in_job))
    raise "IsProcessInJob(current) failed: #{LibC.GetLastError}" if rc == 0
    in_job != 0
  end

  # Records the token this very process runs under. Several Win32 limits (job priority class above
  # NORMAL, for one) depend on which privileges the token holds, so a result is only interpretable next
  # to it. Privileges are listed as NAME+ (enabled) or NAME- (held, disabled).
  def self.token_note : Nil
    token = LibC::HANDLE.null
    if WindowsProbeExtra.OpenProcessToken(WindowsProbeNative.GetCurrentProcess, 0x8_u32, pointerof(token)) == 0 # TOKEN_QUERY
      note("process_token", details(error: LibC.GetLastError))
      return
    end
    elevated = 0_u32
    returned = 0_u32
    WindowsProbeExtra.GetTokenInformation(token, 20_u32, pointerof(elevated).as(Void*), 4_u32, pointerof(returned)) # TokenElevation
    privileges = [] of String
    buffer = Slice(UInt8).new(4096)
    if WindowsProbeExtra.GetTokenInformation(token, 3_u32, buffer.to_unsafe.as(Void*), 4096_u32, pointerof(returned)) != 0 # TokenPrivileges
      buffer.to_unsafe.as(Pointer(UInt32)).value.times do |i|
        entry = buffer.to_unsafe + 4 + 12 * i
        luid = ((entry + 4).as(Pointer(Int32)).value.to_u64 << 32) | entry.as(Pointer(UInt32)).value.to_u64
        attributes = (entry + 8).as(Pointer(UInt32)).value
        name_buffer = Slice(UInt16).new(128)
        length = 128_u32
        name = WindowsProbeExtra.LookupPrivilegeNameW(Pointer(UInt16).null, pointerof(luid), name_buffer.to_unsafe, pointerof(length)) != 0 ? String.from_utf16(name_buffer[0, length.to_i]) : "luid:#{luid}"
        privileges << "#{name}#{(attributes & 0x2_u32) != 0 ? "+" : "-"}"
      end
    end
    LibC.CloseHandle(token)
    note("process_token", details(is_elevated: elevated,
      priority_class_hex: WindowsProbeExtra.GetPriorityClass(WindowsProbeNative.GetCurrentProcess).to_s(16),
      has_se_increase_base_priority: privileges.any?(&.starts_with?("SeIncreaseBasePriorityPrivilege")),
      privileges: privileges.join(",")))
  end

  # In-process bisection of a rejected job priority request: the same priority class asked through the
  # raw API with one variable changed at a time. Result per variant is "ok" or the Win32 error.
  def self.raw_priority_variants(priority : UInt32) : String
    variants = [] of String
    {% for spec in [{"basic", 2, 0_u32}, {"extended", 9, 0_u32}, {"extended+kill_on_close", 9, 0x2000_u32}] %}
      begin
        job = LibC.CreateJobObjectW(Pointer(LibC::SECURITY_ATTRIBUTES).null, Pointer(UInt16).null)
        if job.null?
          variants << "{{ spec[0].id }}=create_failed:#{LibC.GetLastError}"
        else
          info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
          info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS | {{ spec[2] }}
          info.basicLimitInformation.priorityClass = priority
          size = {{ spec[1] }} == 2 ? sizeof(LibC::JOBOBJECT_BASIC_LIMIT_INFORMATION) : sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
          rc = LibC.SetInformationJobObject(job, LibC::JOBOBJECTINFOCLASS.new({{ spec[1] }}), pointerof(info).as(Void*), size.to_u32)
          variants << "{{ spec[0].id }}=#{rc != 0 ? "ok" : LibC.GetLastError.to_s}"
          LibC.CloseHandle(job)
        end
      end
    {% end %}
    variants.join(" ")
  end

  # Informational: would a HIGH job priority class be accepted right now? Recorded at section boundaries so a
  # change in the process's state over the run (the kit's request is rejected, an identical one from a fresh
  # process is not) can be located.
  def self.priority_checkpoint(label : String) : Nil
    note("priority_checkpoint_#{label}", details(high: raw_priority_variants(ProcessSupervision::Windows::Job::PriorityClass::High.value)))
  end

  def self.wait_until(timeout : Time::Span, interval : Time::Span = 10.milliseconds, & : -> Bool) : Bool
    deadline = Time.instant + timeout
    loop do
      return true if yield
      return false if Time.instant >= deadline
      sleep interval
    end
  end

  def self.wait_until_dead(pid : Int64, timeout : Time::Span = 3.seconds) : ProcessHandle::Observation
    last = ProcessHandle.observe(pid)
    wait_until(timeout) do
      last = ProcessHandle.observe(pid)
      last.terminated?
    end
    last
  end

  def self.wait_for_limit_kind(job : ProcessSupervision::Windows::Job,
                               kind : ProcessSupervision::Windows::Job::Limit::Event::Kind,
                               timeout : Time::Span = 3.seconds) : ProcessSupervision::Windows::Job::Limit::Event?
    found = nil.as(ProcessSupervision::Windows::Job::Limit::Event?)
    wait_until(timeout, 20.milliseconds) do
      found = job.limit_events.find { |event| event.kind == kind }
      !found.nil?
    end
    found
  end

  def self.query_current_job_extended : LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION?
    return nil unless parent_in_job?
    info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
    returned = 0_u32
    rc = WindowsProbeExtra.QueryInformationJobObject(LibC::HANDLE.null, JOB_EXTENDED_LIMIT_CLASS,
      pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32, pointerof(returned))
    rc == 0 ? nil : info
  end

  def self.query_extended(job : ProcessSupervision::Windows::Job) : LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
    returned = 0_u32
    rc = WindowsProbeExtra.QueryInformationJobObject(job.probe_native_handle, JOB_EXTENDED_LIMIT_CLASS,
      pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32, pointerof(returned))
    raise "QueryInformationJobObject(extended) failed: #{LibC.GetLastError}" if rc == 0
    info
  end

  def self.query_u32_class(job : ProcessSupervision::Windows::Job, info_class : UInt32, count : Int32 = 1) : Array(UInt32)
    values = Slice(UInt32).new(count, 0_u32)
    returned = 0_u32
    rc = WindowsProbeExtra.QueryInformationJobObject(job.probe_native_handle, info_class,
      values.to_unsafe.as(Void*), (sizeof(UInt32) * count).to_u32, pointerof(returned))
    raise "QueryInformationJobObject(#{info_class}) failed: #{LibC.GetLastError}" if rc == 0
    values.to_a
  end

  def self.raw_job_process_ids(job : ProcessSupervision::Windows::Job, slots : Int32) : NamedTuple(
    ok: Bool, error: UInt32, returned: UInt32, assigned: UInt32, listed: UInt32, ids: Array(UInt64))
    raise ArgumentError.new("slots must be non-negative") if slots < 0
    header = 8
    bytes = Bytes.new(header + slots * sizeof(LibC::SizeT), 0_u8)
    returned = 0_u32
    rc = WindowsProbeExtra.QueryInformationJobObject(job.probe_native_handle, JOB_BASIC_PROCESS_ID_LIST_CLASS,
      bytes.to_unsafe.as(Void*), bytes.size.to_u32, pointerof(returned))
    error = rc == 0 ? LibC.GetLastError : 0_u32
    assigned = bytes.to_unsafe.as(UInt32*).value
    listed = (bytes.to_unsafe + sizeof(UInt32)).as(UInt32*).value
    ids = [] of UInt64
    count = {listed.to_i, slots}.min
    ptr = (bytes.to_unsafe + header).as(LibC::SizeT*)
    count.times { |i| ids << ptr[i].to_u64 }
    {ok: rc != 0, error: error, returned: returned, assigned: assigned, listed: listed, ids: ids}
  end

  def self.associate_raw_completion_port(job : ProcessSupervision::Windows::Job, key : UInt64) : LibC::HANDLE
    port = LibC.CreateIoCompletionPort(INVALID_HANDLE_VALUE, LibC::HANDLE.null, Pointer(LibC::ULong).null, 1_u32)
    raise "CreateIoCompletionPort failed: #{LibC.GetLastError}" if port.null?
    associate = LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT.new(
      completionKey: Pointer(Void).new(key), completionPort: port
    )
    rc = LibC.SetInformationJobObject(job.probe_native_handle,
      LibC::JOBOBJECTINFOCLASS::AssociateCompletionPortInformation,
      pointerof(associate).as(Void*), sizeof(LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT).to_u32)
    if rc == 0
      code = LibC.GetLastError
      LibC.CloseHandle(port)
      raise "SetInformationJobObject(completion port) failed: #{code}"
    end
    port
  end

  def self.next_raw_completion(port : LibC::HANDLE, timeout_ms : UInt32 = 250_u32) : NamedTuple(
    ok: Bool, error: UInt32, message: UInt32, key: UInt64, overlapped: UInt64)
    entry = LibC::OVERLAPPED_ENTRY.new
    removed = LibC::ULong.new(0)
    rc = LibC.GetQueuedCompletionStatusEx(port, pointerof(entry), 1, pointerof(removed), timeout_ms, 0)
    error = rc == 0 ? LibC.GetLastError : 0_u32
    {ok: rc != 0 && removed > 0, error: error, message: entry.dwNumberOfBytesTransferred,
     key: entry.lpCompletionKey.to_u64, overlapped: entry.lpOverlapped.address.to_u64}
  end

  def self.configure_write_notification(job : ProcessSupervision::Windows::Job, bytes_limit : UInt64) : NamedTuple(ok: Bool, error: UInt32)
    info = WindowsProbeExtra::JobNotificationLimit.new
    info.io_write_bytes_limit = bytes_limit
    info.limit_flags = JOB_OBJECT_LIMIT_JOB_WRITE_BYTES
    rc = LibC.SetInformationJobObject(job.probe_native_handle, LibC::JOBOBJECTINFOCLASS.new(JOB_NOTIFICATION_LIMIT_CLASS.to_i32),
      pointerof(info).as(Void*), sizeof(WindowsProbeExtra::JobNotificationLimit).to_u32)
    {ok: rc != 0, error: rc == 0 ? LibC.GetLastError : 0_u32}
  end

  def self.query_limit_violation(job : ProcessSupervision::Windows::Job) : NamedTuple(
    ok: Bool, error: UInt32, limit_flags: UInt32, violation_flags: UInt32, write_bytes: UInt64, write_limit: UInt64)
    info = WindowsProbeExtra::JobLimitViolation.new
    returned = 0_u32
    rc = WindowsProbeExtra.QueryInformationJobObject(job.probe_native_handle, JOB_LIMIT_VIOLATION_CLASS,
      pointerof(info).as(Void*), sizeof(WindowsProbeExtra::JobLimitViolation).to_u32, pointerof(returned))
    {ok: rc != 0, error: rc == 0 ? LibC.GetLastError : 0_u32,
     limit_flags: info.limit_flags, violation_flags: info.violation_limit_flags,
     write_bytes: info.io_write_bytes, write_limit: info.io_write_bytes_limit}
  end

  def self.run_fault_helper(kind : String) : Hash(String, JSON::Any)
    marker = File.join(workdir, "win-fault-#{kind}-#{Process.pid}-#{Random.rand(1_000_000)}.json")
    child = Process.new(self_exe, ["--child", "fault-case", kind, marker])
    reaped = false
    begin
      status = child.wait
      reaped = true
      raise "fault helper did not publish #{kind}" unless File.exists?(marker)
      payload = JSON.parse(File.read(marker)).as_h
      payload["helper_status"] = JSON::Any.new(status.system_exit_status.to_i64)
      payload
    ensure
      child.try { |c| cleanup(c, reaped || false) }
    end
  end

  def self.raw_job_completion_messages(job : ProcessSupervision::Windows::Job,
                                       timeout : Time::Span = 3.seconds) : Array(UInt32)
    # This is used only with a Job constructed without Limits, therefore no
    # shard EventReader is already attached to the Job. Associate before spawn
    # so NEW_PROCESS is not lost to the documented association race.
    port = LibC.CreateIoCompletionPort(INVALID_HANDLE_VALUE, LibC::HANDLE.null, Pointer(LibC::ULong).null, 1_u32)
    raise "CreateIoCompletionPort failed: #{LibC.GetLastError}" if port.null?
    child = nil.as(ProcessSupervision::Child?)
    begin
      associate = LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT.new(
        completionKey: Pointer(Void).new(0x44_u64), completionPort: port
      )
      rc = LibC.SetInformationJobObject(job.probe_native_handle,
        LibC::JOBOBJECTINFOCLASS::AssociateCompletionPortInformation,
        pointerof(associate).as(Void*), sizeof(LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT).to_u32)
      raise "SetInformationJobObject(completion port) failed: #{LibC.GetLastError}" if rc == 0
      child = job.spawn(self_exe, ["--child", "sleep", "240"])
      child.wait(3.seconds)
      messages = [] of UInt32
      deadline = Time.instant + timeout
      while Time.instant < deadline && !messages.includes?(JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO)
        entry = LibC::OVERLAPPED_ENTRY.new
        removed = LibC::ULong.new(0)
        if LibC.GetQueuedCompletionStatusEx(port, pointerof(entry), 1, pointerof(removed), 100_u32, 0) != 0 && removed > 0
          messages << entry.dwNumberOfBytesTransferred
        end
      end
      messages
    ensure
      close_child(child)
      LibC.CloseHandle(port)
    end
  end

  def self.with_job(limits : ProcessSupervision::Windows::Job::Limits? = nil, &)
    job = ProcessSupervision.job(limits)
    begin
      yield job
    ensure
      close_job(job)
    end
  end

  def self.raw_environment_entries : Array(String)
    block = LibC.GetEnvironmentStringsW
    return [] of String if block.null?
    entries = [] of String
    begin
      cursor = block
      loop do
        length = 0
        while cursor[length] != 0_u16
          length += 1
        end
        break if length == 0
        entries << String.from_utf16(Slice.new(cursor, length))
        cursor += length + 1
      end
    ensure
      LibC.FreeEnvironmentStringsW(block)
    end
    entries
  end

  def self.duplicate_native_handle(handle : LibC::HANDLE) : LibC::HANDLE
    current = WindowsProbeNative.GetCurrentProcess
    duplicate = LibC::HANDLE.null
    rc = LibC.DuplicateHandle(current, handle, current, pointerof(duplicate), 0_u32, 0, LibC::DUPLICATE_SAME_ACCESS)
    raise "DuplicateHandle failed: #{LibC.GetLastError}" if rc == 0
    duplicate
  end

  def self.workdir : String
    @@workdir ||= ENV["PROCESS_PROBE_WORKDIR"]? || File.join(Dir.current, "process-windows-probe-#{Process.pid}")
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
        j.field "platform", "windows"
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

  def self.wait_for_file(path : String, timeout : Time::Span = 3.seconds) : Bool
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

  def self.close_child(child : ProcessSupervision::Child?) : Nil
    return unless child
    begin
      child.handle.kill unless child.handle.closed?
    rescue
    end
    begin
      child.wait(3.seconds)
    rescue
    end
    begin
      child.close
    rescue
    end
  end

  def self.close_job(job : ProcessSupervision::Windows::Job?) : Nil
    return unless job
    begin
      job.close
    rescue
    end
  end

  def self.child_mode : NoReturn
    case ARGV[1]?
    when "sleep"
      ms = ARGV[2]?.try(&.to_i?) || 500
      sleep({ms, 7000}.min.milliseconds)
      exit 0
    when "args"
      marker = ARGV[2]? || raise "missing marker"
      File.write(marker, {"args" => ARGV[3..], "cwd" => Dir.current,
                          "probe_env" => ENV["PROCESS_PROBE_TOKEN"]?,
                          "inherit_canary" => ENV["PROCESS_PROBE_INHERIT"]?}.to_json)
      exit 0
    when "check-handle"
      marker = ARGV[2]? || raise "missing marker"
      handle_number = (ARGV[3]? || raise "missing handle number").to_u64
      probe_handle = LibC::HANDLE.new(handle_number)
      flags = 0_u32
      rc = WindowsProbeNative.GetHandleInformation(probe_handle, pointerof(flags))
      code = rc == 0 ? LibC.GetLastError : 0_u32
      File.write(marker, {"accessible" => (rc != 0), "error" => code, "flags" => flags}.to_json)
      exit 0
    when "check-handles"
      marker = ARGV[2]? || raise "missing marker"
      handles = (ARGV[3]? || "").split(',').reject(&.empty?).map(&.to_u64)
      accessible = [] of UInt64
      errors = {} of String => UInt32
      handles.each do |value|
        flags = 0_u32
        rc = WindowsProbeNative.GetHandleInformation(LibC::HANDLE.new(value), pointerof(flags))
        accessible << value if rc != 0
        errors[value.to_s] = rc == 0 ? LibC.GetLastError : 0_u32
      end
      File.write(marker, {"count" => accessible.size, "accessible" => accessible, "errors" => errors}.to_json)
      exit 0
    when "spawn-grandchild"
      marker = ARGV[2]? || raise "missing marker"
      grandchild = Process.new(self_exe, ["--child", "sleep", "6500"])
      File.write(marker, grandchild.pid.to_s)
      sleep 6500.milliseconds
      exit 0
    when "job-controller"
      # A separate controller owns the *only* Job Object HANDLE. The parent
      # deliberately terminates this controller after it publishes the child
      # PID, proving kernel kill-on-owner-death rather than an orderly close.
      marker = ARGV[2]? || raise "missing marker"
      job = ProcessSupervision.job
      child = job.spawn(self_exe, ["--child", "sleep", "6500"])
      File.write(marker, child.pid.to_s)
      sleep 6500.milliseconds
      exit 0
    when "exit-code"
      code = (ARGV[2]? || "0").to_i
      exit code
    when "exit-u32"
      code = (ARGV[2]? || "0").to_u32
      WindowsProbeExtra.ExitProcess(code)
    when "cpu-spin"
      ms = (ARGV[2]? || "800").to_i.clamp(1, 20000)
      marker = ARGV[3]?
      deadline = Time.instant + ms.milliseconds
      value = 0x1234_5678_u64
      while Time.instant < deadline
        50_000.times { value = value &* 6364136223846793005_u64 &+ 1442695040888963407_u64 }
      end
      File.write(marker, value.to_s) if marker
      exit 0
    when "mem-grow"
      marker = ARGV[2]? || raise "missing marker"
      target_mb = (ARGV[3]? || "192").to_i.clamp(4, 512)
      chunks = [] of Bytes
      allocated = 0
      begin
        while allocated < target_mb
          block = Bytes.new(4 * 1024 * 1024, 0x5a_u8)
          chunks << block
          allocated += 4
          File.write(marker, {"allocated_mb" => allocated, "state" => "running"}.to_json)
          sleep 5.milliseconds
        end
        File.write(marker, {"allocated_mb" => allocated, "state" => "complete"}.to_json)
        sleep 250.milliseconds
        exit 0
      rescue ex
        begin
          File.write(marker, {"allocated_mb" => allocated, "state" => "exception", "class" => ex.class.name}.to_json)
        rescue
        end
        exit 73
      end
    when "io-work"
      marker = ARGV[2]? || raise "missing marker"
      path = ARGV[3]? || raise "missing output path"
      payload = Bytes.new(64 * 1024, 0x6b_u8)
      File.open(path, "w") do |io|
        64.times { io.write(payload) }
        io.flush
      end
      File.open(path) do |io|
        buffer = Bytes.new(64 * 1024)
        while io.read(buffer) > 0
        end
      end
      File.write(marker, {"bytes" => File.size(path)}.to_json)
      exit 0
    when "env-dump"
      marker = ARGV[2]? || raise "missing marker"
      keys = ARGV[3..]
      selected = {} of String => String?
      keys.each { |key| selected[key] = ENV[key]? }
      File.write(marker, {"values" => selected, "size" => ENV.size}.to_json)
      exit 0
    when "stdio-check"
      marker = ARGV[2]? || raise "missing marker"
      result = {} of String => String
      {"stdin" => 0xfffffff6_u32, "stdout" => 0xfffffff5_u32, "stderr" => 0xfffffff4_u32}.each do |name, kind|
        handle = LibC.GetStdHandle(kind)
        flags = 0_u32
        valid = !handle.null? && handle != INVALID_HANDLE_VALUE && WindowsProbeNative.GetHandleInformation(handle, pointerof(flags)) != 0
        result["#{name}_valid"] = valid.to_s
        result["#{name}_handle"] = handle.address.to_u64.to_s
        result["#{name}_flags"] = flags.to_s
      end
      File.write(marker, result.to_json)
      exit 0
    when "priority-info"
      marker = ARGV[2]? || raise "missing marker"
      value = WindowsProbeExtra.GetPriorityClass(WindowsProbeNative.GetCurrentProcess)
      File.write(marker, {"priority" => value}.to_json)
      exit value == 0 ? 74 : 0
    when "abnormal-exit"
      sleep 120.milliseconds
      WindowsProbeExtra.ExitProcess(0xc0000005_u32)
    when "raw-breakaway-attempt"
      marker = ARGV[2]? || raise "missing marker"
      command_line = Process.quote_windows([self_exe, "--child", "sleep", "1200"]).to_utf16
      startup = LibC::STARTUPINFOW.new
      startup.cb = sizeof(LibC::STARTUPINFOW).to_u32
      info = LibC::PROCESS_INFORMATION.new
      Errno.value = Errno::NONE
      rc = LibC.CreateProcessW(Pointer(UInt16).null, command_line.to_unsafe,
        Pointer(LibC::SECURITY_ATTRIBUTES).null, Pointer(LibC::SECURITY_ATTRIBUTES).null,
        0, CREATE_BREAKAWAY_FROM_JOB, Pointer(Void).null, Pointer(UInt16).null,
        pointerof(startup), pointerof(info))
      code = rc == 0 ? LibC.GetLastError : 0_u32
      pid = rc == 0 ? 0_u32 : info.dwProcessId
      if rc != 0
        LibC.CloseHandle(info.hThread) unless info.hThread.null?
        LibC.CloseHandle(info.hProcess) unless info.hProcess.null?
      end
      File.write(marker, {"success" => (rc != 0), "error" => code, "pid" => pid}.to_json)
      exit 0
    when "env-block-dump"
      marker = ARGV[2]? || raise "missing marker"
      entries = raw_environment_entries
      File.write(marker, {"entries" => entries}.to_json)
      exit 0
    when "std-fallback-controller"
      marker = ARGV[2]? || raise "missing marker"
      old_in = LibC.GetStdHandle(0xfffffff6_u32)
      old_out = LibC.GetStdHandle(0xfffffff5_u32)
      old_err = LibC.GetStdHandle(0xfffffff4_u32)
      result = {} of String => String
      begin
        WindowsProbeExtra.SetStdHandle(0xfffffff6_u32, LibC::HANDLE.null)
        WindowsProbeExtra.SetStdHandle(0xfffffff5_u32, LibC::HANDLE.null)
        WindowsProbeExtra.SetStdHandle(0xfffffff4_u32, LibC::HANDLE.null)
        job = ProcessSupervision.job
        child_marker = marker + ".child"
        child = nil.as(ProcessSupervision::Child?)
        begin
          child = job.spawn(self_exe, ["--child", "stdio-check", child_marker])
          status = child.wait(3.seconds)
          payload = File.exists?(child_marker) ? JSON.parse(File.read(child_marker)) : JSON.parse("{}")
          result["spawned"] = (status.try(&.success?) == true).to_s
          %w(stdin_valid stdout_valid stderr_valid).each { |key| result[key] = payload[key]?.try(&.as_s?) || "false" }
        ensure
          close_child(child)
          close_job(job)
        end
      ensure
        WindowsProbeExtra.SetStdHandle(0xfffffff6_u32, old_in)
        WindowsProbeExtra.SetStdHandle(0xfffffff5_u32, old_out)
        WindowsProbeExtra.SetStdHandle(0xfffffff4_u32, old_err)
      end
      File.write(marker, result.to_json)
      exit 0
    when "fault-case"
      kind = ARGV[2]? || raise "missing fault kind"
      marker = ARGV[3]? || raise "missing marker"
      result = ""
      begin
        case kind
        when "wait-unregister"
          target = Process.new(self_exe, ["--child", "sleep", "1200"])
          begin
            handle = ProcessHandle.open(target.pid)
            begin
              result = handle.as(ProcessHandle::Windows).probe_registered_wait_unregister_failure(30.milliseconds)
            ensure
              handle.close rescue nil
            end
          ensure
            cleanup(target)
          end
        when "wait-wake"
          target = Process.new(self_exe, ["--child", "sleep", "1200"])
          begin
            handle = ProcessHandle.open(target.pid)
            begin
              result = handle.as(ProcessHandle::Windows).probe_registered_wait_wake_failure(250.milliseconds)
            ensure
              handle.close rescue nil
            end
          ensure
            cleanup(target)
          end
        when "spawn-cleanup-first-error"
          ProcessHandle::Windows.probe_arm_spawn_cleanup_double_failure
          job = ProcessSupervision.job
          begin
            begin
              job.spawn(self_exe, ["--child", "sleep", "1000"])
              result = "unexpected_success"
            rescue ex
              result = "#{ex.class.name}:#{ex.message}"
            end
          ensure
            ProcessHandle::Windows.probe_clear_spawn_cleanup_faults
            close_job(job)
          end
        when "block-open-first-error"
          begin
            ProcessHandle.open(Process.pid) do |handle|
              handle.as(ProcessHandle::Windows).probe_force_native_close_without_publish
              raise "injected block failure"
            end
            result = "unexpected_success"
          rescue ex
            result = "#{ex.class.name}:#{ex.message}"
          end
        when "owner-close"
          handle = ProcessHandle.open(Process.pid)
          handle.as(ProcessHandle::Windows).probe_force_native_close_without_publish
          begin
            handle.close
            result = "unexpected_success"
          rescue ex
            result = "#{ex.class.name}:#{ex.message}"
          end
        when "job-close"
          job = ProcessSupervision.job
          job.probe_force_native_job_close_without_publish
          begin
            job.close
            result = "unexpected_success"
          rescue ex
            result = "#{ex.class.name}:#{ex.message}"
          end
        when "event-stop"
          job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 2_u32))
          job.probe_force_event_port_closed_before_stop
          begin
            job.close
            result = "unexpected_success"
          rescue ex
            result = "#{ex.class.name}:#{ex.message}"
          end
        when "event-final-close"
          job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 2_u32))
          job.probe_force_event_port_closed_after_stop
          begin
            job.close
            result = "unexpected_success"
          rescue ex
            result = "#{ex.class.name}:#{ex.message}"
          end
        else
          result = "unknown_fault_kind"
        end
      rescue ex
        result = "outer:#{ex.class.name}:#{ex.message}"
      end
      File.write(marker, {"kind" => kind, "result" => result}.to_json)
      exit 0
    else
      STDERR.puts "unknown child mode"
      exit 64
    end
  end

  def self.wait_result(handle : ProcessHandle, timeout : Time::Span) : String
    begin
      handle.wait(timeout).to_s
    rescue ex
      "#{ex.class.name}:#{ex.message}"
    end
  end

  # Expanded native qualification matrix. Test children and Jobs belong to this run.
  # Every case records independent pass/fail evidence; a failure does not hide
  # later results. Platform/runtime interpretation belongs to the handback.
  def self.run_expanded : Nil
    test("identity_generation_proof_rules") do
      pid = Process.pid.to_i64
      a = ProcessHandle::Identity.new(pid, 101_u64)
      equal = ProcessHandle::Identity.new(pid, 101_u64)
      changed = ProcessHandle::Identity.new(pid, 102_u64)
      unknown = ProcessHandle::Identity.new(pid, nil)
      other = ProcessHandle::Identity.new(pid + 1_i64, 101_u64)
      ok = a.same_pid?(changed) && a.same_pid?(unknown) && a.same_process?(equal) &&
           !a.same_process?(changed) && !a.same_process?(unknown) &&
           !unknown.same_process?(unknown) && !a.same_pid?(other) && !a.same_process?(other)
      {ok, details(equal_proven: a.same_process?(equal), changed_rejected: !a.same_process?(changed),
        tokenless_rejected: !a.same_process?(unknown), different_pid_rejected: !a.same_process?(other))}
    end

    test("pid_validation_all_public_entrypoints") do
      rejected = [] of String
      [-1, 0].each do |pid|
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
        begin
          ProcessHandle.open(pid) { |h| h.pid }
        rescue ArgumentError
          rejected << "open:#{pid}"
        end
      end
      {rejected.size == 6, details(rejected: rejected.join(","))}
    end

    test("nonexistent_pid_open_classification") do
      outcome = "opened"
      begin
        ProcessHandle.open(Int32::MAX) { |h| outcome = "opened:#{h.pid}" }
      rescue ProcessHandle::Error::NoSuchProcess
        outcome = "no_such_process"
      rescue ProcessHandle::Error::AccessDenied
        outcome = "access_denied"
      end
      {outcome == "no_such_process", details(outcome: outcome)}
    end

    test("scoped_native_handle_exception_and_owner_survival") do
      h = ProcessHandle.current
      caught = false
      begin
        begin
          h.as(ProcessHandle::Windows).with_native_handle(ProcessHandle::Windows::Access::QueryLimitedInformation) do |raw|
            raise "scope-canary" unless WindowsProbeNative.GetProcessId(raw) == Process.pid
            raise "scope-canary"
          end
        rescue ex : Exception
          caught = ex.message == "scope-canary"
        end
        fresh = h.as(ProcessHandle::Windows).with_native_handle(ProcessHandle::Windows::Access::QueryLimitedInformation) do |raw|
          WindowsProbeNative.GetProcessId(raw)
        end
        {caught && fresh == Process.pid && h.alive?, details(original_exception: caught, fresh_pid: fresh, owner_alive: h.alive?)}
      ensure
        h.close
      end
    end

    test("handle_block_scope_ensures_close_on_exception") do
      observed = nil.as(ProcessHandle?)
      caught = false
      begin
        ProcessHandle.open(Process.pid) do |h|
          observed = h
          raise "block-close-canary"
        end
      rescue ex
        caught = ex.message == "block-close-canary"
      end
      {caught && observed.try(&.closed?) == true,
       details(original_exception: caught, closed_after_raise: observed.try(&.closed?))}
    end

    test("closed_handle_rejects_effects_and_close_is_idempotent") do
      h = ProcessHandle.current
      h.close
      h.close
      rejected = [] of String
      begin
        h.alive?
      rescue ProcessHandle::Error::Closed
        rejected << "alive"
      end
      begin
        h.wait(0.milliseconds)
      rescue ProcessHandle::Error::Closed
        rejected << "wait"
      end
      begin
        h.kill
      rescue ProcessHandle::Error::Closed
        rejected << "kill"
      end
      {h.closed? && rejected.size == 3, details(rejected: rejected.join(","), closed: h.closed?)}
    end

    test("arbitrary_handle_terminate_is_unsupported") do
      h = ProcessHandle.current
      begin
        rejected = false
        begin
          h.terminate
        rescue ProcessHandle::Error::Unsupported
          rejected = true
        end
        {rejected && h.alive?, details(rejected_as_unsupported: rejected, process_alive: h.alive?)}
      ensure
        h.close
      end
    end

    test("handle_negative_zero_timeout_and_repeated_completion") do
      child = Process.new(self_exe, ["--child", "sleep", "700"])
      h = nil.as(ProcessHandle?)
      reaped = false
      begin
        h = ProcessHandle.open(child.pid)
        before_identity = ProcessHandle.lookup(child.pid)
        same_before = before_identity.try { |snapshot| h.identity.same_process?(snapshot) } == true
        invalid = false
        begin
          h.wait(-1.millisecond)
        rescue ArgumentError
          invalid = true
        end
        zero = h.wait(0.milliseconds)
        first = h.wait(3.seconds)
        second = h.wait(0.milliseconds)
        status = child.wait
        reaped = true
        after = ProcessHandle.observe(child.pid)
        {invalid && same_before && !zero && first && second && status.success? && after.state.dead?,
         details(negative_rejected: invalid, zero_return: zero, first_wait: first,
           repeated_wait: second, same_before_exit: same_before, after_state: after.state,
           after_exit_alive: h.alive?)}
      ensure
        h.try &.close
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("child_timeout_then_cached_status") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "550"])
        short = child.wait(20.milliseconds)
        status = child.wait(3.seconds)
        again = child.wait(3.seconds)
        cached = child.status
        {short.nil? && !status.nil? && status == again && status == cached && status.try(&.success?) == true,
         details(short_timed_out: short.nil?, status_cached: status == cached,
           repeat_equal: status == again, child_exit: status.try(&.exit_code?))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("child_collector_ten_fibers_same_cached_status") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "500"])
        results = Channel(String).new(10)
        10.times do
          spawn do
            begin
              status = child.not_nil!.wait(3.seconds)
              results.send(status ? "#{status.exit_code?}" : "timeout")
            rescue ex
              results.send("error:#{ex.class.name}")
            end
          end
        end
        observed = Array(String).new(10) { results.receive }
        cached = child.status
        {observed.all? { |r| r == "0" } && cached.try(&.success?) == true,
         details(results: observed.join(","), cached: !cached.nil?)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("child_close_never_closes_shared_job_or_sibling") do
      job = ProcessSupervision.job
      first = nil.as(ProcessSupervision::Child?)
      sibling = nil.as(ProcessSupervision::Child?)
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "200"])
        sibling = job.spawn(self_exe, ["--child", "sleep", "1100"])
        result = first.wait(3.seconds)
        first.close
        alive = sibling.handle.alive?
        second = sibling.wait(3.seconds)
        {result.try(&.success?) == true && !job.closed? && alive && second.try(&.success?) == true,
         details(first_finished: result.try(&.success?), sibling_alive_after_first_close: alive,
           job_closed: job.closed?, sibling_finished: second.try(&.success?))}
      ensure
        close_child(first)
        close_child(sibling)
        close_job(job)
      end
    end

    test("job_empty_fast_path_shutdown_no_termination") do
      job = ProcessSupervision.job
      begin
        report = job.shutdown(grace: 0.milliseconds, kill_after: 0.milliseconds, close: true)
        {report.drained? && report.closed? && !report.kill_requested? && !report.terminate_requested?,
         details(drained: report.drained?, closed: report.closed?, kill_requested: report.kill_requested?,
           terminate_requested: report.terminate_requested?)}
      ensure
        close_job(job)
      end
    end

    test("job_wait_empty_timeout_and_negative_validation") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "900"])
        negative = false
        begin
          job.wait_empty(-1.millisecond)
        rescue ArgumentError
          negative = true
        end
        short = job.wait_empty(30.milliseconds)
        status = child.wait(3.seconds)
        drained = job.wait_empty(2.seconds)
        {negative && !short && drained && status.try(&.success?) == true,
         details(negative_rejected: negative, short_wait: short, drained: drained)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_closed_state_rejects_queries_and_spawn") do
      job = ProcessSupervision.job
      job.close
      job.close
      rejected = [] of String
      begin
        job.accounting
      rescue ProcessSupervision::Error::Closed
        rejected << "accounting"
      end
      begin
        job.empty?
      rescue ProcessSupervision::Error::Closed
        rejected << "empty"
      end
      begin
        job.spawn(self_exe, ["--child", "sleep", "100"])
      rescue ProcessSupervision::Error::Closed
        rejected << "spawn"
      end
      {job.closed? && rejected.size == 3, details(closed: job.closed?, rejected: rejected.join(","))}
    end

    test("job_close_false_shutdown_retains_owner") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "2000"])
        report = job.shutdown(grace: 50.milliseconds, kill_after: 3.seconds, close: false)
        closed_in_report = report.closed?
        still_open = !job.closed?
        terminated = child.handle.wait(2.seconds)
        job.close
        {report.kill_requested? && report.drained? && !closed_in_report && still_open && terminated && job.closed?,
         details(kill_requested: report.kill_requested?, drained: report.drained?,
           report_closed: closed_in_report, owner_stayed_open: still_open, terminated: terminated)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_terminate_explicitly_unsupported") do
      job = ProcessSupervision.job
      begin
        unsupported = false
        begin
          job.terminate
        rescue ProcessSupervision::Error::Unsupported
          unsupported = true
        end
        {unsupported && job.empty?, details(unsupported: unsupported, empty: job.empty?)}
      ensure
        close_job(job)
      end
    end

    test("job_two_sibling_kill_and_accounting") do
      job = ProcessSupervision.job
      first = nil.as(ProcessSupervision::Child?)
      second = nil.as(ProcessSupervision::Child?)
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "4000"])
        second = job.spawn(self_exe, ["--child", "sleep", "4000"])
        before = job.accounting
        job.kill
        a = first.handle.wait(3.seconds)
        b = second.handle.wait(3.seconds)
        first.wait(3.seconds)
        second.wait(3.seconds)
        drained = job.wait_empty(2.seconds)
        job.kill
        {before.active_processes >= 2 && a && b && drained,
         details(before_active: before.active_processes, before_total: before.total_processes,
           first_terminated: a, second_terminated: b, drained: drained)}
      ensure
        close_child(first)
        close_child(second)
        close_job(job)
      end
    end

    test("spawn_invalid_command_rollback_allows_reuse") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        failure = "no_error"
        begin
          child = job.spawn(File.join(workdir, "does-not-exist-process-probe.exe"))
        rescue ex
          failure = "#{ex.class.name}:#{ex.message}"
        end
        empty_after_failure = job.empty?
        recovered = job.spawn(self_exe, ["--child", "sleep", "110"])
        status = recovered.wait(3.seconds)
        recovered.close
        {child.nil? && failure != "no_error" && empty_after_failure && status.try(&.success?) == true,
         details(failure: failure, empty_after_failure: empty_after_failure,
           subsequent_spawn_success: status.try(&.success?))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_limit_validation_rejects_invalid_policy") do
      invalid = [] of String
      {
        {"zero_active", ProcessSupervision::Windows::Job::Limits.new(active_processes: 0_u32)},
        {"zero_memory", ProcessSupervision::Windows::Job::Limits.new(job_memory: 0_u64)},
        {"negative_cpu", ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: -1.0)},
        {"over_cpu", ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 100.1)},
      }.each do |name, limits|
        begin
          ProcessSupervision.job(limits).close
        rescue ArgumentError
          invalid << name
        end
      end
      {invalid.size == 4, details(rejected: invalid.join(","))}
    end

    test("clear_environment_prevents_parent_variable_inheritance") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      marker = File.join(workdir, "win-clear-env-#{Process.pid}.json")
      previous = ENV["PROCESS_PROBE_INHERIT"]?
      begin
        ENV["PROCESS_PROBE_INHERIT"] = "should-not-cross"
        child = job.spawn(self_exe, ["--child", "args", marker, "clear-env"],
          clear_env: true, env: {"PROCESS_PROBE_TOKEN" => "explicit-only"})
        status = child.wait(3.seconds)
        payload = JSON.parse(File.read(marker))
        absent = payload["inherit_canary"].raw.nil?
        {status.try(&.success?) == true && absent && payload["probe_env"].as_s == "explicit-only",
         details(child_exited: status.try(&.success?), inherited_canary: !absent,
           explicit_token: payload["probe_env"].as_s)}
      ensure
        if value = previous
          ENV["PROCESS_PROBE_INHERIT"] = value
        else
          ENV.delete("PROCESS_PROBE_INHERIT")
        end
        close_child(child)
        close_job(job)
      end
    end

    test("multi_raw_thread_waiters_and_owner_close") do
      child = Process.new(self_exe, ["--child", "sleep", "650"])
      handle = nil.as(ProcessHandle?)
      reaped = false
      begin
        handle = ProcessHandle.open(child.pid)
        results = Array(String).new(6, "not_returned")
        started = Atomic(Int32).new(0)
        threads = Array(Thread).new(6) do |i|
          Thread.new do
            started.add(1)
            results[i] = wait_result(handle.not_nil!, 2.seconds)
          end
        end
        deadline = Time.instant + 1.second
        until started.get == 6 || Time.instant >= deadline
          sleep 1.millisecond
        end
        sleep 25.milliseconds
        handle.close
        threads.each(&.join)
        status = child.wait
        reaped = true
        accepted = results.all? { |x| x == "true" || x.starts_with?("ProcessHandle::Error::Closed:") }
        {accepted && status.success?, details(outcomes: results.join(","), started: started.get,
          note: "admission/close race: valid admitted result or Closed; not a positive overlap proof")}
      ensure
        handle.try &.close
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("repeated_job_creation_and_close") do
      closed = 0
      12.times do
        job = ProcessSupervision.job
        begin
          empty = job.empty?
          job.close
          job.close
          closed += 1 if empty && job.closed?
        ensure
          close_job(job)
        end
      end
      {closed == 12, details(completed_cycles: closed)}
    end

    # Observational resource diagnostics cannot be a pass/fail leak proof:
    # Crystal and Windows runtime worker pools may alter HANDLE counts.
    begin
      before = 0_u32
      after = 0_u32
      if WindowsProbeNative.GetProcessHandleCount(WindowsProbeNative.GetCurrentProcess, pointerof(before)) != 0
        40.times { ProcessHandle.observe(Process.pid); ProcessHandle.lookup(Process.pid) }
        if WindowsProbeNative.GetProcessHandleCount(WindowsProbeNative.GetCurrentProcess, pointerof(after)) != 0
          note("win32_handle_count_observation", details(before: before, after: after,
            delta: after.to_i64 - before.to_i64, samples: 40,
            interpretation: "observational only; no bounded-leak proof without baseline noise controls"))
        end
      end
    rescue ex
      note("win32_handle_count_observation", details(error: ex.message, classification: "unavailable"))
    end
  end

  # Revision 5: exhaustive-by-capability qualification. This is intentionally
  # broader than the shard's existing specs. It tests public contracts,
  # adjacent Win32 semantics the implementation depends on, bounded stress,
  # and probe-only fault paths that cannot be reached through normal APIs.
  def self.run_exhaustive : Nil
    test("pid_upper_bound_rejected_without_wraparound") do
      aliased = (1_u64 << 32) + Process.pid.to_u64
      outcome = "accepted"
      state = ""
      begin
        observed = ProcessHandle.observe(aliased.to_i64)
        state = observed.state.to_s
      rescue ex : ArgumentError
        outcome = "argument_error"
      rescue ex : ProcessHandle::Error
        outcome = ex.class.name
      end
      {outcome == "argument_error", details(pid: aliased, outcome: outcome, state: state,
        contract: "native DWORD PID overflow must be rejected, never truncated")}
    end

    test("observe_lookup_open_generation_consistency") do
      pid = Process.pid.to_i64
      observed = ProcessHandle.observe(pid)
      looked = ProcessHandle.lookup(pid)
      handle = ProcessHandle.open(pid)
      begin
        ok = observed.live? && looked != nil && observed.identity != nil &&
             observed.identity.not_nil!.same_process?(looked.not_nil!) &&
             handle.identity.same_process?(looked.not_nil!) && handle.alive?
        {ok, details(observe_generation: observed.identity.try(&.generation),
          lookup_generation: looked.try(&.generation), handle_generation: handle.identity.generation)}
      ensure
        handle.close
      end
    end

    test("retained_handle_survives_natural_exit_identity_stable") do
      child = Process.new(self_exe, ["--child", "sleep", "180"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      before = handle.identity
      begin
        waited = handle.wait(2.seconds)
        status = child.wait
        reaped = true
        after = handle.identity
        {waited && !handle.alive? && before == after && status.success?,
         details(pid: child.pid, waited: waited, alive_after: handle.alive?, generation: after.generation,
           exit: status.system_exit_status)}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("identity_alive_tracks_natural_exit") do
      child = Process.new(self_exe, ["--child", "sleep", "220"])
      reaped = false
      begin
        identity = ProcessHandle.lookup(child.pid).not_nil!
        before = identity.alive?
        status = child.wait
        reaped = true
        after = identity.alive?
        {before && status.success? && !after, details(before: before, after: after, exit: status.system_exit_status)}
      ensure
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("kill_sets_137_and_handle_wait_completes") do
      child = Process.new(self_exe, ["--child", "sleep", "3000"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      begin
        handle.kill
        ready = handle.wait(2.seconds)
        status = child.wait
        reaped = true
        {ready && status.system_exit_status == 137_u32 && !handle.alive?,
         details(ready: ready, status: status.system_exit_status, alive: handle.alive?)}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("repeated_kill_after_exit_is_idempotent") do
      child = Process.new(self_exe, ["--child", "sleep", "2400"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      begin
        handle.kill
        child.wait
        reaped = true
        errors = [] of String
        3.times do
          begin
            handle.kill
          rescue ex
            errors << "#{ex.class.name}:#{ex.message}"
          end
        end
        {errors.empty?, details(errors: errors.join(" | "), alive: handle.alive?)}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("scoped_handle_requested_rights_and_identity") do
      handle = ProcessHandle.current
      begin
        native_pid = 0_u32
        handle.as(ProcessHandle::Windows).with_native_handle(
          ProcessHandle::Windows::Access::Synchronize | ProcessHandle::Windows::Access::QueryLimitedInformation
        ) do |native|
          native_pid = WindowsProbeNative.GetProcessId(native)
        end
        {native_pid == Process.pid, details(native_pid: native_pid, expected_pid: Process.pid)}
      ensure
        handle.close
      end
    end

    test("scoped_native_handle_survives_owner_close") do
      handle = ProcessHandle.current
      owner_closed = false
      native_pid = 0_u32
      handle.as(ProcessHandle::Windows).with_native_handle(ProcessHandle::Windows::Access::Synchronize) do |native|
        handle.close
        owner_closed = handle.closed?
        native_pid = WindowsProbeNative.GetProcessId(native)
      end
      {owner_closed && native_pid == Process.pid, details(owner_closed: owner_closed, native_pid: native_pid)}
    end

    test("scoped_native_handle_after_owner_close_rejected") do
      handle = ProcessHandle.current
      handle.close
      outcome = "accepted"
      begin
        handle.as(ProcessHandle::Windows).with_native_handle(ProcessHandle::Windows::Access::Synchronize) { |native| native.address }
      rescue ex : ProcessHandle::Error::Closed
        outcome = "closed"
      rescue ex
        outcome = ex.class.name
      end
      {outcome == "closed", details(outcome: outcome,
        contract: "closed retained owner must not admit fresh native effects")}
    end

    test("concurrent_open_observe_lookup_same_generation") do
      pid = Process.pid.to_i64
      results = Array(UInt64?).new(48, nil)
      errors = [] of String
      lock = Thread::Mutex.new
      threads = Array(Thread).new(16) do |index|
        Thread.new do
          3.times do |round|
            begin
              case round
              when 0
                h = ProcessHandle.open(pid)
                begin
                  results[index * 3 + round] = h.identity.generation
                ensure
                  h.close
                end
              when 1
                results[index * 3 + round] = ProcessHandle.observe(pid).identity.try(&.generation)
              else
                results[index * 3 + round] = ProcessHandle.lookup(pid).try(&.generation)
              end
            rescue ex
              lock.synchronize { errors << "#{ex.class.name}:#{ex.message}" }
            end
          end
        end
      end
      threads.each(&.join)
      unique = results.compact.uniq
      {errors.empty? && unique.size == 1 && results.none?(&.nil?),
       details(errors: errors.join(" | "), unique_generations: unique.size, samples: results.size)}
    end

    test("open_close_churn_handle_count_bounded") do
      before = current_handle_count
      100.times do
        h = ProcessHandle.current
        h.alive?
        h.close
      end
      GC.collect
      sleep 40.milliseconds
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      {delta.abs <= 4, details(before: before, after: after, delta: delta, iterations: 100)}
    end

    test("observe_lookup_churn_handle_count_bounded") do
      before = current_handle_count
      150.times do
        ProcessHandle.observe(Process.pid)
        ProcessHandle.lookup(Process.pid)
      end
      GC.collect
      sleep 40.milliseconds
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      {delta.abs <= 4, details(before: before, after: after, delta: delta, iterations: 150)}
    end

    test("wait_nil_blocks_until_natural_exit") do
      child = Process.new(self_exe, ["--child", "sleep", "160"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      begin
        start = Time.instant
        ready = handle.wait
        elapsed = Time.instant - start
        status = child.wait
        reaped = true
        {ready && status.success? && elapsed >= 80.milliseconds,
         details(ready: ready, elapsed_ms: elapsed.total_milliseconds, status: status.system_exit_status)}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("wait_timeout_does_not_consume_future_completion") do
      child = Process.new(self_exe, ["--child", "sleep", "420"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      begin
        first = handle.wait(30.milliseconds)
        second = handle.wait(2.seconds)
        status = child.wait
        reaped = true
        {(!first) && second && status.success?, details(first: first, second: second, exit: status.system_exit_status)}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("wait_zero_poll_live_then_dead") do
      child = Process.new(self_exe, ["--child", "sleep", "240"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      begin
        before = handle.wait(Time::Span.zero)
        status = child.wait
        reaped = true
        after = handle.wait(Time::Span.zero)
        {(!before) && status.success? && after, details(before: before, after: after)}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("wait_many_timeouts_then_completion") do
      child = Process.new(self_exe, ["--child", "sleep", "420"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      begin
        elapsed = [] of Float64
        early = Array(Bool).new(8) do
          started = Time.instant
          value = handle.wait(15.milliseconds)
          elapsed << (Time.instant - started).total_milliseconds
          value
        end
        final = handle.wait(2.seconds)
        status = child.wait
        reaped = true
        {early.none? && elapsed.all? { |ms| ms < 150.0 } && final && status.success?,
         details(early_true: early.count(true), final: final, per_wait_ms: elapsed.map { |ms| ms.round(3) }.join(","), max_wait_ms: elapsed.max.round(3))}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("wait_close_barrier_native_threads") do
      child = Process.new(self_exe, ["--child", "sleep", "900"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      results = [] of String
      lock = Thread::Mutex.new
      ready = Atomic(Int32).new(0)
      go = Atomic(Bool).new(false)
      threads = Array(Thread).new(8) do
        Thread.new do
          ready.add(1)
          until go.get
            Thread.yield
          end
          value = wait_result(handle, 2.seconds)
          lock.synchronize { results << value }
        end
      end
      ready_ok = wait_until(1.second) { ready.get == 8 }
      go.set(true)
      sleep 10.milliseconds
      handle.close
      threads.each(&.join)
      status = child.wait
      reaped = true
      allowed = results.all? { |r| r == "true" || r.includes?("Closed") }
      {ready_ok && allowed && status.success? && results.size == 8,
       details(ready_ok: ready_ok, results: results.sort.join(" | "), count: results.size)}
    ensure
      handle.try &.close rescue nil
      child.try { |c| cleanup(c, reaped || false) }
    end

    test("wait_kill_barrier_native_threads") do
      child = Process.new(self_exe, ["--child", "sleep", "2000"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      results = [] of String
      lock = Thread::Mutex.new
      ready = Atomic(Int32).new(0)
      go = Atomic(Bool).new(false)
      threads = Array(Thread).new(8) do
        Thread.new do
          ready.add(1)
          until go.get
            Thread.yield
          end
          value = wait_result(handle, 3.seconds)
          lock.synchronize { results << value }
        end
      end
      ready_ok = wait_until(1.second) { ready.get == 8 }
      go.set(true)
      sleep 10.milliseconds
      handle.kill
      threads.each(&.join)
      status = child.wait
      reaped = true
      {ready_ok && results.size == 8 && results.all? { |r| r == "true" } && status.system_exit_status == 137_u32,
       details(ready_ok: ready_ok, results: results.join(","), exit: status.system_exit_status)}
    ensure
      handle.try &.close rescue nil
      child.try { |c| cleanup(c, reaped || false) }
    end

    test("wait_post_exit_many_callers_immediate") do
      child = Process.new(self_exe, ["--child", "exit-code", "0"])
      reaped = false
      handle = ProcessHandle.open(child.pid)
      begin
        status = child.wait
        reaped = true
        start = Time.instant
        results = Array(Bool).new(32) { handle.wait(1.second) }
        elapsed = Time.instant - start
        {status.success? && results.all? && elapsed < 1.second,
         details(all_ready: results.all?, elapsed_ms: elapsed.total_milliseconds, count: results.size)}
      ensure
        handle.close rescue nil
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("registered_wait_unregister_failure_surfaces_without_crash") do
      payload = run_fault_helper("wait-unregister")
      result = payload["result"].as_s
      {result.includes?("UnregisterWaitEx") && !result.includes?("unexpected_success"), details(result: result)}
    end

    test("registered_wait_callback_wake_failure_surfaces_without_crash") do
      payload = run_fault_helper("wait-wake")
      result = payload["result"].as_s
      {result.includes?("registered process wait") && !result.includes?("unexpected_success"), details(result: result)}
    end

    test("owner_checked_close_failure_surfaces") do
      payload = run_fault_helper("owner-close")
      result = payload["result"].as_s
      {result.includes?("CloseHandle(process)") && !result.includes?("unexpected_success"), details(result: result)}
    end

    test("job_checked_close_failure_surfaces") do
      payload = run_fault_helper("job-close")
      result = payload["result"].as_s
      {result.includes?("CloseHandle(Job)") && !result.includes?("unexpected_success"), details(result: result)}
    end

    test("job_event_stop_failure_surfaces") do
      payload = run_fault_helper("event-stop")
      result = payload["result"].as_s
      {result.includes?("PostQueuedCompletionStatus") && !result.includes?("unexpected_success"), details(result: result)}
    end

    test("job_event_final_close_failure_surfaces") do
      payload = run_fault_helper("event-final-close")
      result = payload["result"].as_s
      {result.includes?("CloseHandle(Job event completion port)") && !result.includes?("unexpected_success"), details(result: result)}
    end

    test("child_status_nil_before_wait") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "220"])
        before = child.status
        status = child.wait(2.seconds)
        {before.nil? && status != nil && child.status == status,
         details(before_nil: before.nil?, after_cached: child.status == status)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("child_wait_zero_timeout_then_completion") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "260"])
        first = child.wait(Time::Span.zero)
        second = child.wait(2.seconds)
        {first.nil? && second.try(&.success?) == true && child.status == second,
         details(first_nil: first.nil?, second: second.try(&.system_exit_status))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("child_close_idempotent") do
      job = ProcessSupervision.job
      child = job.spawn(self_exe, ["--child", "exit-code", "0"])
      child.wait(2.seconds)
      child.close
      second = "ok"
      begin
        child.close
      rescue ex
        second = "#{ex.class.name}:#{ex.message}"
      end
      job.close
      {second == "ok", details(second_close: second)}
    end

    test("child_nonzero_status_preserved") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "exit-code", "37"])
        status = child.wait(2.seconds)
        cached = child.wait(Time::Span.zero)
        {status.try(&.system_exit_status) == 37_u32 && cached.try(&.system_exit_status) == 37_u32,
         details(status: status.try(&.system_exit_status), cached: cached.try(&.system_exit_status))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("child_wait_and_close_race_documented_outcomes") do
      job = ProcessSupervision.job
      child = job.spawn(self_exe, ["--child", "sleep", "320"])
      results = [] of String
      lock = Thread::Mutex.new
      waiter = Thread.new do
        begin
          value = child.wait(2.seconds)
          lock.synchronize { results << "wait:#{value.try(&.system_exit_status)}" }
        rescue ex
          lock.synchronize { results << "wait_error:#{ex.class.name}" }
        end
      end
      closer = Thread.new do
        Thread.sleep(20.milliseconds)
        begin
          child.close
          lock.synchronize { results << "close:ok" }
        rescue ex
          lock.synchronize { results << "close_error:#{ex.class.name}" }
        end
      end
      waiter.join
      closer.join
      close_job(job)
      {results.size == 2 && results.none? { |r| r.includes?("Segmentation") || r.includes?("Invalid memory") },
       details(results: results.sort.join(" | "))}
    end

    test("job_kill_after_close_rejected") do
      job = ProcessSupervision.job
      job.close
      outcome = "accepted"
      begin
        job.kill
      rescue ex : ProcessSupervision::Error::Closed
        outcome = "closed"
      rescue ex
        outcome = ex.class.name
      end
      {outcome == "closed", details(outcome: outcome, contract: "post-close effects fail closed")}
    end

    test("job_limit_events_after_close_rejected") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 2_u32))
      job.close
      outcome = "accepted"
      begin
        job.limit_events
      rescue ex : ProcessSupervision::Error::Closed
        outcome = "closed"
      rescue ex
        outcome = ex.class.name
      end
      {outcome == "closed", details(outcome: outcome, contract: "post-close state queries fail closed")}
    end

    test("job_accounting_after_close_rejected") do
      job = ProcessSupervision.job
      job.close
      outcome = "accepted"
      begin
        job.accounting
      rescue ex : ProcessSupervision::Error::Closed
        outcome = "closed"
      rescue ex
        outcome = ex.class.name
      end
      {outcome == "closed", details(outcome: outcome)}
    end

    test("job_adopt_after_close_rejected") do
      target = Process.new(self_exe, ["--child", "sleep", "800"])
      reaped = false
      handle = ProcessHandle.open(target.pid)
      job = ProcessSupervision.job
      job.close
      outcome = "accepted"
      begin
        job.adopt(handle)
      rescue ex : ProcessSupervision::Error::Closed
        outcome = "closed"
      rescue ex
        outcome = ex.class.name
      end
      handle.close rescue nil
      cleanup(target, reaped)
      {outcome == "closed", details(outcome: outcome)}
    end

    test("closed_process_handle_cannot_be_adopted") do
      target = Process.new(self_exe, ["--child", "sleep", "800"])
      reaped = false
      handle = ProcessHandle.open(target.pid)
      handle.close
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.adopt(handle)
      rescue ex : ProcessHandle::Error::Closed
        outcome = "closed"
      rescue ex
        outcome = ex.class.name
      end
      close_job(job)
      cleanup(target, reaped)
      {outcome == "closed", details(outcome: outcome, contract: "closed handle cannot authorize fresh adoption")}
    end

    test("job_wait_empty_after_close_rejected") do
      job = ProcessSupervision.job
      job.close
      outcome = "accepted"
      begin
        job.wait_empty(Time::Span.zero)
      rescue ex : ProcessSupervision::Error::Closed
        outcome = "closed"
      rescue ex
        outcome = ex.class.name
      end
      {outcome == "closed", details(outcome: outcome)}
    end

    test("job_shutdown_negative_grace_rejected_before_close") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.shutdown(grace: -1.millisecond, close: true)
      rescue ArgumentError
        outcome = "argument_error"
      end
      {outcome == "argument_error" && !job.closed?, details(outcome: outcome, closed: job.closed?, contract: "argument validation precedes shutdown mutation")}
    end

    test("job_shutdown_negative_kill_after_rejected_before_close") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.shutdown(kill_after: -1.millisecond, close: true)
      rescue ArgumentError
        outcome = "argument_error"
      end
      {outcome == "argument_error" && !job.closed?, details(outcome: outcome, closed: job.closed?, contract: "argument validation precedes shutdown mutation")}
    end

    test("job_kill_empty_open_is_idempotent") do
      job = ProcessSupervision.job
      begin
        3.times { job.kill }
        {job.empty? && !job.closed?, details(empty: job.empty?, closed: job.closed?)}
      ensure
        job.close
      end
    end

    test("job_close_vs_accounting_parallel_only_success_or_closed") do
      job = ProcessSupervision.job
      child = job.spawn(self_exe, ["--child", "sleep", "600"])
      outcomes = [] of String
      lock = Thread::Mutex.new
      # Each thread queries until it observes the close (bounded), so the close is
      # guaranteed to race live accounting calls rather than follow them.
      threads = Array(Thread).new(12) do
        Thread.new do
          200_000.times do
            begin
              job.accounting
              lock.synchronize { outcomes << "ok" }
            rescue ex : ProcessSupervision::Error::Closed
              lock.synchronize { outcomes << "closed" }
              break
            rescue ex
              lock.synchronize { outcomes << probe_failure_text(ex) }
              break
            end
          end
        end
      end
      sleep 10.milliseconds
      job.close rescue nil
      threads.each(&.join)
      close_child(child)
      unexpected = outcomes.reject { |x| x == "ok" || x == "closed" }
      closed_seen = outcomes.count("closed")
      {unexpected.empty? && closed_seen > 0,
       details(samples: outcomes.size, ok: outcomes.count("ok"), closed: closed_seen, unexpected: unexpected.uniq.first(3).join(" | "))}
    end

    test("spawn_argument_quoting_full_matrix") do
      job = ProcessSupervision.job
      marker = File.join(workdir, "win-argv-full-#{Process.pid}.json")
      args = ["", " ", "alpha beta", "a\tb", "quote\"x", "\\", "\\\\", "trail\\", "a\\\"b",
              "a\\\\\"b", "snowman-☃", "emoji-😀", "line\nbreak", "  leading", "trailing  "]
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "args", marker] + args)
        status = child.wait(3.seconds)
        payload = JSON.parse(File.read(marker))
        actual = payload["args"].as_a.map(&.as_s)
        {status.try(&.success?) == true && actual == args,
         details(exact: actual == args, count: args.size, exit: status.try(&.system_exit_status))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("spawn_environment_case_insensitive_override") do
      ENV["PROCESS_PROBE_CASEKEY"] = "parent"
      job = ProcessSupervision.job
      marker = File.join(workdir, "win-env-case-#{Process.pid}.json")
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "env-dump", marker, "PROCESS_PROBE_CASEKEY"],
          env: {"process_probe_casekey" => "child"})
        status = child.wait(3.seconds)
        values = JSON.parse(File.read(marker))["values"]
        found = values.as_h.values.compact_map(&.as_s?)
        {status.try(&.success?) == true && found == ["child"], details(values: found.join(","))}
      ensure
        ENV.delete("PROCESS_PROBE_CASEKEY")
        close_child(child)
        close_job(job)
      end
    end

    test("spawn_environment_case_insensitive_delete") do
      ENV["PROCESS_PROBE_DELETEKEY"] = "parent"
      job = ProcessSupervision.job
      marker = File.join(workdir, "win-env-delete-#{Process.pid}.json")
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "env-dump", marker, "PROCESS_PROBE_DELETEKEY"],
          env: {"process_probe_deletekey" => nil})
        status = child.wait(3.seconds)
        value = JSON.parse(File.read(marker))["values"].as_h["PROCESS_PROBE_DELETEKEY"]?
        {status.try(&.success?) == true && (value.nil? || value.try(&.raw).nil?), details(deleted: value.nil? || value.try(&.raw).nil?)}
      ensure
        ENV.delete("PROCESS_PROBE_DELETEKEY")
        close_child(child)
        close_job(job)
      end
    end

    test("spawn_environment_empty_value_preserved") do
      job = ProcessSupervision.job
      marker = File.join(workdir, "win-env-empty-#{Process.pid}.json")
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "env-dump", marker, "PROCESS_PROBE_EMPTY"],
          env: {"PROCESS_PROBE_EMPTY" => ""})
        status = child.wait(3.seconds)
        value = JSON.parse(File.read(marker))["values"]["PROCESS_PROBE_EMPTY"]?.try(&.as_s?)
        {status.try(&.success?) == true && value == "", details(value: value.inspect)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("spawn_invalid_env_empty_key_rejected") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn(self_exe, ["--child", "sleep", "10"], env: {"" => "x"})
      rescue ArgumentError
        outcome = "argument_error"
      ensure
        job.close
      end
      {outcome == "argument_error", details(outcome: outcome)}
    end

    test("spawn_invalid_env_equals_key_rejected") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn(self_exe, ["--child", "sleep", "10"], env: {"A=B" => "x"})
      rescue ArgumentError
        outcome = "argument_error"
      ensure
        job.close
      end
      {outcome == "argument_error", details(outcome: outcome)}
    end

    test("spawn_invalid_env_key_nul_rejected") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn(self_exe, ["--child", "sleep", "10"], env: {"A\0B" => "x"})
      rescue ArgumentError
        outcome = "argument_error"
      ensure
        job.close
      end
      {outcome == "argument_error", details(outcome: outcome)}
    end

    test("spawn_invalid_env_value_nul_rejected") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn(self_exe, ["--child", "sleep", "10"], env: {"A" => "x\0y"})
      rescue ArgumentError
        outcome = "argument_error"
      ensure
        job.close
      end
      {outcome == "argument_error", details(outcome: outcome)}
    end

    test("spawn_command_nul_rejected") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn("#{self_exe}\0bad")
      rescue ArgumentError
        outcome = "argument_error"
      ensure
        job.close
      end
      {outcome == "argument_error", details(outcome: outcome)}
    end

    test("spawn_argument_nul_rejected") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn(self_exe, ["abc\0def"])
      rescue ArgumentError
        outcome = "argument_error"
      ensure
        job.close
      end
      {outcome == "argument_error", details(outcome: outcome)}
    end

    test("spawn_chdir_nul_rejected") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn(self_exe, ["--child", "sleep", "10"], chdir: "#{workdir}\0bad")
      rescue ArgumentError
        outcome = "argument_error"
      ensure
        job.close
      end
      {outcome == "argument_error", details(outcome: outcome)}
    end

    test("spawn_batch_cmd_case_variants_rejected") do
      variants = ["x.cmd", "X.CMD", "thing.Cmd", "a.cmd. "]
      rejected = [] of String
      job = ProcessSupervision.job
      begin
        variants.each do |name|
          begin
            job.spawn(name)
          rescue ProcessSupervision::Error::Unsupported
            rejected << name
          rescue
          end
        end
        {rejected == variants, details(rejected: rejected.join("|"), expected: variants.join("|"))}
      ensure
        job.close
      end
    end

    test("spawn_batch_bat_trailing_dot_space_rejected") do
      variants = ["x.bat", "X.BAT ", "x.bat...", "x.BaT.  "]
      rejected = [] of String
      job = ProcessSupervision.job
      begin
        variants.each do |name|
          begin
            job.spawn(name)
          rescue ProcessSupervision::Error::Unsupported
            rejected << name
          rescue
          end
        end
        {rejected == variants, details(rejected: rejected.join("|"), expected: variants.join("|"))}
      ensure
        job.close
      end
    end

    test("spawn_missing_chdir_rollback_reusable") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn(self_exe, ["--child", "sleep", "10"], chdir: File.join(workdir, "missing-cwd-never-create"))
      rescue ex : ProcessSupervision::Error::Native
        outcome = "native_error"
      end
      child = job.spawn(self_exe, ["--child", "exit-code", "0"])
      status = child.wait(2.seconds)
      close_child(child)
      job.close
      {outcome == "native_error" && status.try(&.success?) == true, details(outcome: outcome, reusable: status.try(&.success?))}
    end

    test("spawn_unicode_executable_path_and_cwd") do
      dir = File.join(workdir, "unicode dir ☃")
      Dir.mkdir_p(dir)
      copy = File.join(dir, "process probe ☃.exe")
      File.copy(self_exe, copy)
      marker = File.join(dir, "unicode-marker.json")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(copy, ["--child", "args", marker, "雪", "emoji-😀"], chdir: dir)
        status = child.wait(4.seconds)
        payload = JSON.parse(File.read(marker))
        {status.try(&.success?) == true && payload["args"].as_a.map(&.as_s) == ["雪", "emoji-😀"] &&
          Path[payload["cwd"].as_s].expand == Path[dir].expand,
         details(exit: status.try(&.system_exit_status), cwd: payload["cwd"].as_s)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("spawn_standard_handles_are_valid") do
      job = ProcessSupervision.job
      marker = File.join(workdir, "win-stdio-#{Process.pid}.json")
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "stdio-check", marker])
        status = child.wait(3.seconds)
        payload = JSON.parse(File.read(marker)).as_h
        valid = %w[stdin stdout stderr].all? { |name| payload["#{name}_valid"].as_s == "true" }
        {status.try(&.success?) == true && valid, details(valid: valid, fields: payload.size)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("spawn_many_concurrent_children") do
      job = ProcessSupervision.job
      children = [] of ProcessSupervision::Child
      lock = Thread::Mutex.new
      errors = [] of String
      threads = Array(Thread).new(24) do |i|
        Thread.new do
          begin
            child = job.spawn(self_exe, ["--child", "exit-code", (i % 4).to_s])
            lock.synchronize { children << child }
          rescue ex
            lock.synchronize { errors << "#{ex.class.name}:#{ex.message}" }
          end
        end
      end
      threads.each(&.join)
      statuses = children.map { |child| child.wait(3.seconds).try(&.system_exit_status) }
      children.each { |child| child.close rescue nil }
      account = job.accounting
      job.close
      {errors.empty? && children.size == 24 && statuses.compact.size == 24 && account.total_processes >= 24,
       details(children: children.size, errors: errors.join(" | "), total_processes: account.total_processes)}
    end

    test("spawn_empty_command_native_failure_reusable") do
      job = ProcessSupervision.job
      outcome = "accepted"
      begin
        job.spawn("")
      rescue ex
        outcome = ex.class.name
      end
      child = job.spawn(self_exe, ["--child", "exit-code", "0"])
      status = child.wait(2.seconds)
      close_child(child)
      job.close
      {outcome != "accepted" && status.try(&.success?) == true, details(outcome: outcome, reusable: status.try(&.success?))}
    end

    test("raw_completion_port_new_exit_zero_messages") do
      job = ProcessSupervision.job
      begin
        messages = raw_job_completion_messages(job)
        required = [JOB_OBJECT_MSG_NEW_PROCESS, JOB_OBJECT_MSG_EXIT_PROCESS, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO]
        {required.all? { |code| messages.includes?(code) },
         details(messages: messages.join(","), required: required.join(","))}
      ensure
        job.close rescue nil
      end
    end

    test("limits_job_memory_configuration_query") do
      limit = 128_u64 * 1024 * 1024
      with_job(ProcessSupervision::Windows::Job::Limits.new(job_memory: limit)) do |job|
        info = query_extended(job)
        flags = info.basicLimitInformation.limitFlags
        {info.jobMemoryLimit.to_u64 == limit && (flags & JOB_OBJECT_LIMIT_JOB_MEMORY) != 0,
         details(value: info.jobMemoryLimit.to_u64, flags_hex: flags.to_s(16))}
      end
    end

    test("limits_process_memory_configuration_query") do
      limit = 96_u64 * 1024 * 1024
      with_job(ProcessSupervision::Windows::Job::Limits.new(process_memory: limit)) do |job|
        info = query_extended(job)
        flags = info.basicLimitInformation.limitFlags
        {info.processMemoryLimit.to_u64 == limit && (flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY) != 0,
         details(value: info.processMemoryLimit.to_u64, flags_hex: flags.to_s(16))}
      end
    end

    test("limits_active_process_configuration_query") do
      with_job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 7_u32)) do |job|
        info = query_extended(job)
        {info.basicLimitInformation.activeProcessLimit == 7_u32 &&
          (info.basicLimitInformation.limitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) != 0,
         details(value: info.basicLimitInformation.activeProcessLimit,
           flags_hex: info.basicLimitInformation.limitFlags.to_s(16))}
      end
    end

    test("limits_job_user_time_configuration_query") do
      span = 875.milliseconds
      with_job(ProcessSupervision::Windows::Job::Limits.new(job_user_time: span)) do |job|
        info = query_extended(job)
        expected = span.total_nanoseconds.to_i64 // 100
        {info.basicLimitInformation.perJobUserTimeLimit == expected &&
          (info.basicLimitInformation.limitFlags & JOB_OBJECT_LIMIT_JOB_TIME) != 0,
         details(value: info.basicLimitInformation.perJobUserTimeLimit, expected: expected)}
      end
    end

    test("limits_process_user_time_configuration_query") do
      span = 625.milliseconds
      with_job(ProcessSupervision::Windows::Job::Limits.new(process_user_time: span)) do |job|
        info = query_extended(job)
        expected = span.total_nanoseconds.to_i64 // 100
        {info.basicLimitInformation.perProcessUserTimeLimit == expected &&
          (info.basicLimitInformation.limitFlags & JOB_OBJECT_LIMIT_PROCESS_TIME) != 0,
         details(value: info.basicLimitInformation.perProcessUserTimeLimit, expected: expected)}
      end
    end

    test("limits_cpu_rate_configuration_query") do
      with_job(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 12.5)) do |job|
        values = query_u32_class(job, JOB_CPU_RATE_CONTROL_CLASS, 2)
        {values[0] == (CPU_RATE_ENABLE | CPU_RATE_HARD_CAP) && values[1] == 1250_u32,
         details(flags_hex: values[0].to_s(16), rate: values[1])}
      end
    end

    test("limits_priority_idle_configuration_query") do
      with_job(ProcessSupervision::Windows::Job::Limits.new(priority_class: ProcessSupervision::Windows::Job::PriorityClass::Idle)) do |job|
        info = query_extended(job)
        {info.basicLimitInformation.priorityClass == ProcessSupervision::Windows::Job::PriorityClass::Idle.value,
         details(priority: info.basicLimitInformation.priorityClass)}
      end
    end

    test("limits_priority_below_normal_configuration_query") do
      with_job(ProcessSupervision::Windows::Job::Limits.new(priority_class: ProcessSupervision::Windows::Job::PriorityClass::BelowNormal)) do |job|
        info = query_extended(job)
        {info.basicLimitInformation.priorityClass == ProcessSupervision::Windows::Job::PriorityClass::BelowNormal.value,
         details(priority: info.basicLimitInformation.priorityClass)}
      end
    end

    test("limits_priority_normal_configuration_query") do
      with_job(ProcessSupervision::Windows::Job::Limits.new(priority_class: ProcessSupervision::Windows::Job::PriorityClass::Normal)) do |job|
        info = query_extended(job)
        {info.basicLimitInformation.priorityClass == ProcessSupervision::Windows::Job::PriorityClass::Normal.value,
         details(priority: info.basicLimitInformation.priorityClass)}
      end
    end

    test("limits_priority_above_normal_observed") do
      outcome = "configured"
      priority = 0_u32
      begin
        with_job(ProcessSupervision::Windows::Job::Limits.new(priority_class: ProcessSupervision::Windows::Job::PriorityClass::AboveNormal)) do |job|
          priority = query_extended(job).basicLimitInformation.priorityClass
        end
      rescue ex : ProcessSupervision::Error::Native
        outcome = "native_rejected:#{ex.native_code}"
      end
      {outcome.starts_with?("native_rejected") || priority == ProcessSupervision::Windows::Job::PriorityClass::AboveNormal.value,
       details(outcome: outcome, priority: priority, note: "elevation-sensitive outcome recorded")}
    end

    test("limits_priority_high_observed") do
      outcome = "configured"
      priority = 0_u32
      begin
        with_job(ProcessSupervision::Windows::Job::Limits.new(priority_class: ProcessSupervision::Windows::Job::PriorityClass::High)) do |job|
          priority = query_extended(job).basicLimitInformation.priorityClass
        end
      rescue ex : ProcessSupervision::Error::Native
        outcome = "native_rejected:#{ex.native_code}"
      end
      raw = raw_priority_variants(ProcessSupervision::Windows::Job::PriorityClass::High.value)
      {outcome.starts_with?("native_rejected") || priority == ProcessSupervision::Windows::Job::PriorityClass::High.value,
       details(outcome: outcome, priority: priority, raw_same_process: raw, note: "elevation-sensitive outcome recorded")}
    end

    test("limits_ui_single_flags_configuration_query") do
      flags = ProcessSupervision::Windows::Job::UIRestrictions::Handles
      with_job(ProcessSupervision::Windows::Job::Limits.new(ui_restrictions: flags)) do |job|
        value = query_u32_class(job, JOB_BASIC_UI_RESTRICTIONS_CLASS, 1)[0]
        {value == flags.value, details(value_hex: value.to_s(16), expected_hex: flags.value.to_s(16))}
      end
    end

    test("limits_ui_combined_flags_configuration_query") do
      flags = ProcessSupervision::Windows::Job::UIRestrictions::Handles |
              ProcessSupervision::Windows::Job::UIRestrictions::ReadClipboard |
              ProcessSupervision::Windows::Job::UIRestrictions::WriteClipboard |
              ProcessSupervision::Windows::Job::UIRestrictions::SystemParameters |
              ProcessSupervision::Windows::Job::UIRestrictions::DisplaySettings |
              ProcessSupervision::Windows::Job::UIRestrictions::GlobalAtoms |
              ProcessSupervision::Windows::Job::UIRestrictions::Desktop |
              ProcessSupervision::Windows::Job::UIRestrictions::ExitWindows
      with_job(ProcessSupervision::Windows::Job::Limits.new(ui_restrictions: flags)) do |job|
        value = query_u32_class(job, JOB_BASIC_UI_RESTRICTIONS_CLASS, 1)[0]
        {value == flags.value, details(value_hex: value.to_s(16), expected_hex: flags.value.to_s(16))}
      end
    end

    test("limits_all_fields_combined_configuration_query") do
      limits = ProcessSupervision::Windows::Job::Limits.new(
        job_memory: 256_u64 * 1024 * 1024,
        process_memory: 128_u64 * 1024 * 1024,
        active_processes: 9_u32,
        job_user_time: 3.seconds,
        process_user_time: 2.seconds,
        cpu_rate_percent: 75.0,
        priority_class: ProcessSupervision::Windows::Job::PriorityClass::Normal,
        ui_restrictions: ProcessSupervision::Windows::Job::UIRestrictions::Handles
      )
      with_job(limits) do |job|
        info = query_extended(job)
        cpu = query_u32_class(job, JOB_CPU_RATE_CONTROL_CLASS, 2)
        ui = query_u32_class(job, JOB_BASIC_UI_RESTRICTIONS_CLASS, 1)[0]
        expected_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY |
                         JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                         JOB_OBJECT_LIMIT_JOB_TIME | JOB_OBJECT_LIMIT_PROCESS_TIME |
                         JOB_OBJECT_LIMIT_PRIORITY_CLASS
        {((info.basicLimitInformation.limitFlags & expected_flags) == expected_flags) &&
          cpu[1] == 7500_u32 && ui == ProcessSupervision::Windows::Job::UIRestrictions::Handles.value,
         details(flags_hex: info.basicLimitInformation.limitFlags.to_s(16), cpu_rate: cpu[1], ui_hex: ui.to_s(16))}
      end
    end

    test("limits_cpu_rate_fractional_boundary_roundtrip") do
      with_job(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 0.01)) do |job|
        values = query_u32_class(job, JOB_CPU_RATE_CONTROL_CLASS, 2)
        {values[1] == 1_u32, details(rate: values[1], expected: 1)}
      end
    end

    test("limits_cpu_rate_maximum_roundtrip") do
      with_job(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 100.0)) do |job|
        values = query_u32_class(job, JOB_CPU_RATE_CONTROL_CLASS, 2)
        {values[1] == 10_000_u32, details(rate: values[1], expected: 10000)}
      end
    end

    test("process_memory_limit_enforced_and_event") do
      marker = File.join(workdir, "win-proc-mem-limit-#{Process.pid}.json")
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(process_memory: 64_u64 * 1024 * 1024))
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "mem-grow", marker, "160"])
        status = child.wait(5.seconds)
        event = wait_for_limit_kind(job, ProcessSupervision::Windows::Job::Limit::Event::Kind::ProcessMemoryLimit, 2.seconds)
        allocated = File.exists?(marker) ? JSON.parse(File.read(marker))["allocated_mb"]?.try(&.as_i?) : nil
        {event != nil && status != nil, details(event: event.try(&.kind), event_pid: event.try(&.pid),
          exit: status.try(&.system_exit_status), allocated_mb: allocated)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_memory_limit_enforced_and_event") do
      marker = File.join(workdir, "win-job-mem-limit-#{Process.pid}.json")
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(job_memory: 72_u64 * 1024 * 1024))
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "mem-grow", marker, "180"])
        status = child.wait(5.seconds)
        event = wait_for_limit_kind(job, ProcessSupervision::Windows::Job::Limit::Event::Kind::JobMemoryLimit, 2.seconds)
        {event != nil && status != nil, details(event: event.try(&.kind), event_pid: event.try(&.pid),
          exit: status.try(&.system_exit_status))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("process_user_time_limit_enforcement_and_event_observation") do
      limit = 150.milliseconds
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(process_user_time: limit))
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "cpu-spin", "5000"])
        status = child.wait(8.seconds)
        after = job.accounting
        event = wait_for_limit_kind(job, ProcessSupervision::Windows::Job::Limit::Event::Kind::EndOfProcessTime, 1.second)
        terminated_by_limit = status != nil && status.try(&.system_exit_status) != 0_u32
        configured = (query_extended(job).basicLimitInformation.limitFlags & JOB_OBJECT_LIMIT_PROCESS_TIME) != 0
        exercised = status != nil && after.user_time >= limit
        {configured && exercised, details(event: event.try(&.kind), event_pid: event.try(&.pid),
          exit: status.try(&.system_exit_status), configured: configured, enforced: terminated_by_limit,
          configured_limit_ms: limit.total_milliseconds, accounted_user_ms: after.user_time.total_milliseconds,
          parent_job_flags_hex: query_current_job_extended.try(&.basicLimitInformation.limitFlags.to_s(16)),
          classification: terminated_by_limit ? "enforced" : "configured_but_not_enforced_on_host",
          note: "revision 6 showed build 17763 can round-trip this limit without terminating a CPU-bound child; record native behavior rather than fabricating enforcement")}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("native_process_user_time_limit_without_event_reader") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_TIME
        info.basicLimitInformation.perProcessUserTimeLimit = 1_500_000_i64 # 150 ms in 100 ns ticks
        rc = LibC.SetInformationJobObject(job.probe_native_handle, LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        native_error = rc == 0 ? LibC.GetLastError : 0_u32
        queried = query_extended(job)
        child = job.spawn(self_exe, ["--child", "cpu-spin", "5000"]) if rc != 0
        status = child.try(&.wait(8.seconds))
        after = job.accounting
        configured = rc != 0 && (queried.basicLimitInformation.limitFlags & JOB_OBJECT_LIMIT_PROCESS_TIME) != 0 &&
                     queried.basicLimitInformation.perProcessUserTimeLimit == 1_500_000_i64
        enforced = status != nil && status.try(&.system_exit_status) != 0_u32
        exercised = status != nil && after.user_time >= 150.milliseconds
        {configured && exercised, details(rc: rc, error: native_error, configured: configured, enforced: enforced,
          exit: status.try(&.system_exit_status), accounted_user_ms: after.user_time.total_milliseconds,
          parent_job_flags_hex: query_current_job_extended.try(&.basicLimitInformation.limitFlags.to_s(16)),
          classification: enforced ? "enforced" : "configured_but_not_enforced_on_host",
          has_shard_event_reader: false)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_user_time_limit_enforced_and_event") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(job_user_time: 260.milliseconds))
      child = nil.as(ProcessSupervision::Child?)
      begin
        # Job CPU-time limits are enforced by a periodic system-wide pass (7.000 s measured), not when the
        # limit is crossed; spin and wait for two periods. See REVISION-13-CHANGES.md.
        child = job.spawn(self_exe, ["--child", "cpu-spin", "15000"])
        status = child.wait(18.seconds)
        event = wait_for_limit_kind(job, ProcessSupervision::Windows::Job::Limit::Event::Kind::EndOfJobTime, 3.seconds)
        {event != nil && status != nil, details(event: event.try(&.kind), exit: status.try(&.system_exit_status))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("abnormal_exit_event_received") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 4_u32))
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "abnormal-exit"])
        status = child.wait(3.seconds)
        event = wait_for_limit_kind(job, ProcessSupervision::Windows::Job::Limit::Event::Kind::AbnormalExitProcess, 2.seconds)
        {event != nil && status.try(&.exit_reason.access_violation?) == true,
         details(event: event.try(&.kind), event_pid: event.try(&.pid), exit: status.try(&.system_exit_status),
           exit_reason: status.try(&.exit_reason))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("limit_event_snapshot_copy_isolation") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 1_u32))
      first = job.limit_events
      first << ProcessSupervision::Windows::Job::Limit::Event.new(
        ProcessSupervision::Windows::Job::Limit::Event::Kind::ActiveProcessLimit, 123_i64)
      second = job.limit_events
      job.close
      {second.empty?, details(first_size_after_local_mutation: first.size, second_size: second.size)}
    end

    test("accounting_initial_counts") do
      job = ProcessSupervision.job
      begin
        a = job.accounting
        {a.active_processes == 0 && a.total_processes == 0 && a.terminated_processes == 0,
         details(active: a.active_processes, total: a.total_processes, terminated: a.terminated_processes)}
      ensure
        job.close
      end
    end

    test("accounting_active_process_count_exact") do
      job = ProcessSupervision.job
      a = nil.as(ProcessSupervision::Child?)
      b = nil.as(ProcessSupervision::Child?)
      begin
        a = job.spawn(self_exe, ["--child", "sleep", "650"])
        b = job.spawn(self_exe, ["--child", "sleep", "650"])
        count = job.accounting.active_processes
        {count == 2_u32, details(active: count)}
      ensure
        close_child(a)
        close_child(b)
        close_job(job)
      end
    end

    test("accounting_natural_exit_does_not_increment_limit_terminated") do
      job = ProcessSupervision.job
      before = job.accounting
      children = Array(ProcessSupervision::Child).new(4) { |i| job.spawn(self_exe, ["--child", "exit-code", i.to_s]) }
      children.each { |c| c.wait(2.seconds) }
      wait_until(1.second) { job.accounting.active_processes == 0 }
      after = job.accounting
      children.each { |c| c.close rescue nil }
      job.close
      {after.total_processes >= before.total_processes + 4 && after.terminated_processes == before.terminated_processes,
       details(before_total: before.total_processes, after_total: after.total_processes,
         before_terminated: before.terminated_processes, after_terminated: after.terminated_processes,
         contract: "TotalTerminatedProcesses counts limit-violation terminations, not ordinary exits")}
    end

    test("accounting_active_process_limit_violation_increments_terminated") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 1_u32))
      first = nil.as(ProcessSupervision::Child?)
      outcome = "accepted"
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "1200"])
        before = job.accounting
        begin
          job.spawn(self_exe, ["--child", "sleep", "1200"])
        rescue ex
          outcome = "#{ex.class.name}:#{ex.message}"
        end
        after = job.accounting
        {outcome != "accepted" && after.total_processes == before.total_processes &&
          after.terminated_processes == before.terminated_processes,
         details(outcome: outcome, before_total: before.total_processes, after_total: after.total_processes,
           before_terminated: before.terminated_processes, after_terminated: after.terminated_processes,
           classification: "creation_rejected_before_job_association")}
      ensure
        close_child(first)
        close_job(job)
      end
    end

    test("accounting_active_process_limit_adopt_violation_native_behavior") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 1_u32))
      first = nil.as(ProcessSupervision::Child?)
      external = nil.as(Process?)
      handle = nil.as(ProcessHandle?)
      outcome = "accepted"
      reaped = false
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "1500"])
        external = Process.new(self_exe, ["--child", "sleep", "1500"])
        handle = ProcessHandle.open(external.pid)
        before = job.accounting
        begin
          job.adopt(handle)
        rescue ex
          outcome = "#{ex.class.name}:#{ex.message}"
        end
        terminated = handle.wait(2.seconds)
        status = external.wait
        reaped = true
        after = job.accounting
        {outcome != "accepted" && terminated,
         details(outcome: outcome, terminated: terminated, exit: status.system_exit_status,
           before_total: before.total_processes, after_total: after.total_processes,
           before_terminated: before.terminated_processes, after_terminated: after.terminated_processes,
           classification: "post_creation_assign_limit_violation")}
      ensure
        handle.try &.close rescue nil
        external.try { |c| cleanup(c, reaped || false) }
        close_child(first)
        close_job(job)
      end
    end

    test("accounting_user_time_increases_with_cpu_work") do
      job = ProcessSupervision.job
      child = job.spawn(self_exe, ["--child", "cpu-spin", "420"])
      before = job.accounting
      child.wait(3.seconds)
      after = job.accounting
      child.close rescue nil
      job.close
      {after.user_time > before.user_time, details(before_ns: before.user_time.total_nanoseconds,
        after_ns: after.user_time.total_nanoseconds)}
    end

    test("accounting_io_increases_with_file_work") do
      marker = File.join(workdir, "win-io-marker-#{Process.pid}.json")
      path = File.join(workdir, "win-io-data-#{Process.pid}.bin")
      job = ProcessSupervision.job
      child = job.spawn(self_exe, ["--child", "io-work", marker, path])
      before = job.accounting
      child.wait(4.seconds)
      after = job.accounting
      child.close rescue nil
      job.close
      {after.write_operations > before.write_operations && after.read_operations >= before.read_operations &&
        after.write_bytes > before.write_bytes,
       details(write_ops_before: before.write_operations, write_ops_after: after.write_operations,
         write_bytes_before: before.write_bytes, write_bytes_after: after.write_bytes,
         read_ops_before: before.read_operations, read_ops_after: after.read_operations)}
    end

    test("accounting_peak_memory_increases") do
      marker = File.join(workdir, "win-peak-mem-#{Process.pid}.json")
      job = ProcessSupervision.job
      child = job.spawn(self_exe, ["--child", "mem-grow", marker, "48"])
      before = job.accounting
      child.wait(5.seconds)
      after = job.accounting
      child.close rescue nil
      job.close
      {after.peak_job_memory >= before.peak_job_memory && after.peak_process_memory >= before.peak_process_memory &&
        after.peak_job_memory > 0 && after.peak_process_memory > 0,
       details(peak_job_before: before.peak_job_memory, peak_job_after: after.peak_job_memory,
         peak_process_before: before.peak_process_memory, peak_process_after: after.peak_process_memory)}
    end

    test("nested_job_inner_close_kills_inner_only") do
      outer = ProcessSupervision.job
      inner = ProcessSupervision.job
      inner_child = nil.as(ProcessSupervision::Child?)
      outer_sibling = nil.as(ProcessSupervision::Child?)
      begin
        inner_child = outer.spawn(self_exe, ["--child", "sleep", "2500"])
        inner.adopt(inner_child.handle)
        outer_sibling = outer.spawn(self_exe, ["--child", "sleep", "700"])
        inner.close
        inner_dead = inner_child.handle.wait(2.seconds)
        sibling_live = outer_sibling.handle.alive?
        {inner_dead && sibling_live, details(inner_dead: inner_dead, sibling_live: sibling_live)}
      ensure
        close_child(inner_child)
        close_child(outer_sibling)
        close_job(inner)
        close_job(outer)
      end
    end

    test("nested_job_outer_close_kills_inner_member") do
      outer = ProcessSupervision.job
      inner = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = outer.spawn(self_exe, ["--child", "sleep", "2500"])
        inner.adopt(child.handle)
        outer.close
        dead = child.handle.wait(2.seconds)
        {dead, details(dead: dead)}
      ensure
        close_child(child)
        close_job(inner)
        close_job(outer)
      end
    end

    test("nested_job_outer_reusable_after_inner_close") do
      outer = ProcessSupervision.job
      inner = ProcessSupervision.job
      first = nil.as(ProcessSupervision::Child?)
      second = nil.as(ProcessSupervision::Child?)
      begin
        first = outer.spawn(self_exe, ["--child", "sleep", "1200"])
        inner.adopt(first.handle)
        inner.close
        first.wait(2.seconds)
        second = outer.spawn(self_exe, ["--child", "exit-code", "0"])
        status = second.wait(2.seconds)
        {status.try(&.success?) == true && !outer.closed?, details(reused: status.try(&.success?), outer_closed: outer.closed?)}
      ensure
        close_child(first)
        close_child(second)
        close_job(inner)
        close_job(outer)
      end
    end

    test("breakaway_attempt_without_permission_is_rejected") do
      marker = File.join(workdir, "win-breakaway-#{Process.pid}.json")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "raw-breakaway-attempt", marker])
        status = child.wait(3.seconds)
        payload = JSON.parse(File.read(marker))
        success = payload["success"].as_bool
        {status.try(&.success?) == true && !success,
         details(breakaway_success: success, error: payload["error"].as_i, note: "job does not opt into breakaway")}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("native_job_working_set_limit_roundtrip_or_privilege_classification") do
      with_job do |job|
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_WORKINGSET
        info.basicLimitInformation.minimumWorkingSetSize = LibC::SizeT.new(1_048_576_u64)
        info.basicLimitInformation.maximumWorkingSetSize = LibC::SizeT.new(16_777_216_u64)
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        native_error = rc == 0 ? LibC.GetLastError : 0_u32
        queried = query_extended(job)
        flags = queried.basicLimitInformation.limitFlags
        roundtrip = rc != 0 && (flags & JOB_OBJECT_LIMIT_WORKINGSET) != 0 &&
                    queried.basicLimitInformation.minimumWorkingSetSize.to_u64 == 1_048_576_u64 &&
                    queried.basicLimitInformation.maximumWorkingSetSize.to_u64 == 16_777_216_u64
        privilege_classified = rc == 0 && native_error == ERROR_PRIVILEGE_NOT_HELD
        {roundtrip || privilege_classified, details(rc: rc, error: native_error, classification: privilege_classified ? "privilege_not_held" : "configured",
          flags_hex: flags.to_s(16), min: queried.basicLimitInformation.minimumWorkingSetSize,
          max: queried.basicLimitInformation.maximumWorkingSetSize)}
      end
    end

    test("native_job_affinity_limit_roundtrip") do
      with_job do |job|
        process_mask = LibC::DWORD_PTR.new(0)
        system_mask = LibC::DWORD_PTR.new(0)
        rc_mask = WindowsProbeExtra.GetProcessAffinityMask(WindowsProbeNative.GetCurrentProcess,
          pointerof(process_mask), pointerof(system_mask))
        raise "GetProcessAffinityMask failed" if rc_mask == 0
        bits = process_mask.to_u64
        lowest = bits & (~bits &+ 1_u64)
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_AFFINITY
        info.basicLimitInformation.affinity = LibC::ULONG_PTR.new(lowest)
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        queried = query_extended(job)
        actual = queried.basicLimitInformation.affinity.to_u64
        {rc != 0 && actual == lowest, details(requested: lowest.to_s(16), actual: actual.to_s(16), system: system_mask.to_u64.to_s(16))}
      end
    end

    test("native_job_scheduling_class_roundtrip") do
      with_job do |job|
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SCHEDULING_CLASS
        info.basicLimitInformation.schedulingClass = 4_u32
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        queried = query_extended(job)
        {rc != 0 && queried.basicLimitInformation.schedulingClass == 4_u32,
         details(actual: queried.basicLimitInformation.schedulingClass, flags_hex: queried.basicLimitInformation.limitFlags.to_s(16))}
      end
    end

    test("native_job_die_on_unhandled_exception_flag_roundtrip") do
      with_job do |job|
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        expected = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        info.basicLimitInformation.limitFlags = expected
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        flags = query_extended(job).basicLimitInformation.limitFlags
        {rc != 0 && (flags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION) != 0,
         details(flags_hex: flags.to_s(16))}
      end
    end

    test("native_job_breakaway_ok_flag_roundtrip") do
      with_job do |job|
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        flags = query_extended(job).basicLimitInformation.limitFlags
        {rc != 0 && (flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK) != 0, details(flags_hex: flags.to_s(16))}
      end
    end

    test("native_job_silent_breakaway_flag_roundtrip") do
      with_job do |job|
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        flags = query_extended(job).basicLimitInformation.limitFlags
        {rc != 0 && (flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0, details(flags_hex: flags.to_s(16))}
      end
    end

    test("native_job_explicit_breakaway_succeeds_when_enabled") do
      marker = File.join(workdir, "win-breakaway-enabled-#{Process.pid}.json")
      job = ProcessSupervision.job
      direct = nil.as(ProcessSupervision::Child?)
      escaped = nil.as(ProcessHandle?)
      begin
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        raise "SetInformationJobObject breakaway failed" if rc == 0
        direct = job.spawn(self_exe, ["--child", "raw-breakaway-attempt", marker])
        status = direct.wait(3.seconds)
        payload = JSON.parse(File.read(marker))
        success = payload["success"].as_bool
        escaped_pid = payload["pid"].as_i64
        if success && escaped_pid > 0
          escaped = ProcessHandle.open(escaped_pid)
        end
        in_inner = escaped.try { |h| h.as(ProcessHandle::Windows).probe_is_in_job(job.probe_native_handle) }
        {status.try(&.success?) == true && success && escaped != nil && in_inner == false,
         details(create_success: success, escaped_pid: escaped_pid, in_inner_job: in_inner)}
      ensure
        begin
          escaped.try(&.kill) rescue nil
        end
        begin
          escaped.try(&.wait(2.seconds)) rescue nil
        end
        begin
          escaped.try(&.close) rescue nil
        end
        close_child(direct)
        close_job(job)
      end
    end

    test("native_job_silent_breakaway_descendant_escapes_inner_job") do
      marker = File.join(workdir, "win-silent-breakaway-#{Process.pid}.txt")
      job = ProcessSupervision.job
      direct = nil.as(ProcessSupervision::Child?)
      escaped = nil.as(ProcessHandle?)
      begin
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
        rc = LibC.SetInformationJobObject(job.probe_native_handle,
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        raise "SetInformationJobObject silent breakaway failed" if rc == 0
        direct = job.spawn(self_exe, ["--child", "spawn-grandchild", marker])
        raise "grandchild marker missing" unless wait_for_file(marker)
        escaped_pid = File.read(marker).strip.to_i64
        escaped = ProcessHandle.open(escaped_pid)
        in_inner = escaped.as(ProcessHandle::Windows).probe_is_in_job(job.probe_native_handle)
        direct.handle.kill rescue nil
        direct.wait(2.seconds) rescue nil
        {in_inner == false && escaped.alive?, details(escaped_pid: escaped_pid, in_inner_job: in_inner, escaped_alive: escaped.alive?)}
      ensure
        begin
          escaped.try(&.kill) rescue nil
        end
        begin
          escaped.try(&.wait(2.seconds)) rescue nil
        end
        begin
          escaped.try(&.close) rescue nil
        end
        close_child(direct)
        close_job(job)
      end
    end

    test("job_kill_on_close_waits_for_last_duplicate_job_handle") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      duplicate = LibC::HANDLE.null
      begin
        current = WindowsProbeNative.GetCurrentProcess
        ok = LibC.DuplicateHandle(current, job.probe_native_handle, current, pointerof(duplicate),
          0_u32, 0, 0x00000002_u32)
        raise "DuplicateHandle(Job) failed: #{LibC.GetLastError}" if ok == 0
        child = job.spawn(self_exe, ["--child", "sleep", "3000"])
        job.close
        alive_with_duplicate = child.handle.alive?
        LibC.CloseHandle(duplicate); duplicate = LibC::HANDLE.null
        terminated_after_last_close = child.handle.wait(2.seconds)
        {alive_with_duplicate && terminated_after_last_close,
         details(alive_with_duplicate: alive_with_duplicate, terminated_after_last_close: terminated_after_last_close)}
      ensure
        LibC.CloseHandle(duplicate) unless duplicate.null?
        close_child(child)
        close_job(job)
      end
    end

    test("supervised_spawn_does_not_inherit_job_handle") do
      marker = File.join(workdir, "win-job-handle-inherit-#{Process.pid}.json")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        raw = job.probe_native_handle.address.to_u64
        child = job.spawn(self_exe, ["--child", "check-handle", marker, raw.to_s])
        status = child.wait(3.seconds)
        payload = JSON.parse(File.read(marker))
        accessible = payload["accessible"].as_bool
        {status.try(&.success?) == true && !accessible,
         details(job_handle_value: raw, accessible_in_child: accessible, error: payload["error"].as_i)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("stress_process_handle_open_wait_close_100_cycles") do
      before = current_handle_count
      failures = [] of String
      100.times do |i|
        child = Process.new(self_exe, ["--child", "exit-code", "0"])
        reaped = false
        begin
          h = ProcessHandle.open(child.pid)
          begin
            failures << "wait:#{i}" unless h.wait(2.seconds)
          ensure
            h.close rescue failures << "close:#{i}"
          end
          status = child.wait
          reaped = true
          failures << "status:#{i}" unless status.success?
        ensure
          child.try { |c| cleanup(c, reaped || false) }
        end
      end
      GC.collect
      sleep 80.milliseconds
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      {failures.empty? && delta.abs <= 8,
       details(failures: failures.first(10).join(","), before: before, after: after, delta: delta, cycles: 100)}
    end

    test("stress_job_event_reader_create_close_75_cycles") do
      before = current_handle_count
      failures = [] of String
      75.times do |i|
        begin
          job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 2_u32))
          job.limit_events
          job.close
        rescue ex
          failures << "#{i}:#{ex.class.name}"
        end
      end
      GC.collect
      sleep 80.milliseconds
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      {failures.empty? && delta.abs <= 8,
       details(failures: failures.first(10).join(","), before: before, after: after, delta: delta, cycles: 75)}
    end

    test("stress_job_without_event_reader_create_close_75_cycles") do
      before = current_handle_count
      failures = [] of String
      75.times do |i|
        begin
          job = ProcessSupervision.job
          job.close
        rescue ex
          failures << "#{i}:#{ex.class.name}"
        end
      end
      GC.collect
      sleep 80.milliseconds
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      {failures.empty? && delta.abs <= 8,
       details(failures: failures.first(10).join(","), before: before, after: after, delta: delta, cycles: 75)}
    end

    test("stress_crystal_raw_thread_join_handle_cleanup_classification") do
      before = current_handle_count
      75.times do
        Thread.new { nil }.join
      end
      GC.collect
      sleep 80.milliseconds
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      fixed = delta.abs <= 8
      known_join_leak_shape = delta >= 67 && delta <= 83
      {fixed || known_join_leak_shape,
       details(before: before, after: after, delta: delta, cycles: 75,
         classification: fixed ? "runtime_join_cleanup_no_growth" : "runtime_join_per_thread_handle_growth")}
    end

    test("stress_crystal_raw_thread_self_cleanup_without_join") do
      before = current_handle_count
      completed = Atomic(Int32).new(0)
      75.times do
        Thread.new { completed.add(1) }
      end
      deadline = Time.instant + 3.seconds
      until completed.get == 75 || Time.instant >= deadline
        Thread.sleep(1.millisecond)
      end
      Thread.sleep(80.milliseconds)
      GC.collect
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      {completed.get == 75 && delta.abs <= 8,
       details(before: before, after: after, delta: delta, completed: completed.get, cycles: 75)}
    end

    test("stress_failed_spawn_rollback_75_cycles") do
      before = current_handle_count
      job = ProcessSupervision.job
      errors = 0
      75.times do |i|
        begin
          job.spawn(File.join(workdir, "never-exists-#{i}.exe"))
        rescue ProcessSupervision::Error::Native
          errors += 1
        end
      end
      child = job.spawn(self_exe, ["--child", "exit-code", "0"])
      status = child.wait(2.seconds)
      close_child(child)
      job.close
      GC.collect
      sleep 80.milliseconds
      after = current_handle_count
      delta = after.to_i64 - before.to_i64
      {errors == 75 && status.try(&.success?) == true && delta.abs <= 8,
       details(errors: errors, reusable: status.try(&.success?), before: before, after: after, delta: delta)}
    end
  end

  def self.probe_priority_applied(expected : ProcessSupervision::Windows::Job::PriorityClass, label : String)
    marker = File.join(workdir, "priority-#{label}-#{Process.pid}.json")
    job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(priority_class: expected))
    child = nil.as(ProcessSupervision::Child?)
    begin
      child = job.spawn(self_exe, ["--child", "priority-info", marker])
      status = child.wait(2.seconds)
      actual = JSON.parse(File.read(marker))["priority"].as_i.to_u32
      {status.try(&.success?) == true && actual == expected.value, details(actual: actual, expected: expected.value)}
    ensure
      close_child(child)
      close_job(job)
    end
  end

  def self.run_deep_native_matrix : Nil
    test("protected_system_process_access_classification") do
      outcome = "unknown"
      begin
        handle = ProcessHandle.open(4)
        begin
          begin
            handle.as(ProcessHandle::Windows).with_native_handle(ProcessHandle::Windows::Access::Terminate) { |_| outcome = "terminate_right_opened" }
          rescue ex : ProcessHandle::Error::AccessDenied
            outcome = "scoped_access_denied"
          rescue ex : ProcessHandle::Error::NoSuchProcess
            outcome = "gone"
          end
        ensure
          handle.close
        end
      rescue ex : ProcessHandle::Error::AccessDenied
        outcome = "observer_access_denied"
      rescue ex : ProcessHandle::Error::NoSuchProcess
        outcome = "gone"
      end
      {outcome.in?({"terminate_right_opened", "scoped_access_denied", "observer_access_denied", "gone"}),
       details(outcome: outcome, note: "PID 4 is never terminated; this records native access classification")}
    end

    test("scoped_native_duplicate_is_noninheritable") do
      h = ProcessHandle.current
      flags = 0_u32
      begin
        h.as(ProcessHandle::Windows).with_native_handle(ProcessHandle::Windows::Access::Synchronize) do |raw|
          raise "GetHandleInformation failed" if WindowsProbeNative.GetHandleInformation(raw, pointerof(flags)) == 0
        end
        {flags & 1_u32 == 0, details(flags: flags, inherit: (flags & 1_u32) != 0)}
      ensure
        h.close
      end
    end

    test("child_wait_error_fanout_after_handle_close") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "1800"])
        child.handle.close
        entered = Channel(Nil).new(8)
        outcomes = Channel(Exception).new(8)
        8.times do
          spawn do
            entered.send(nil)
            begin
              child.not_nil!.wait
              outcomes.send(Exception.new("unexpected success"))
            rescue ex
              outcomes.send(ex)
            end
          end
        end
        8.times { entered.receive }
        errors = Array(Exception).new(8) { outcomes.receive }
        same = errors.map(&.object_id).uniq.size == 1
        typed = errors.all? { |e| e.is_a?(ProcessHandle::Error::Closed) }
        {same && typed, details(same_error_object: same, typed_closed: typed, count: errors.size)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("child_raw_thread_wait_returns_status") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "exit-code", "37"])
        result = Channel(String).new(1)
        thread = Thread.new do
          begin
            status = child.not_nil!.wait(3.seconds)
            result.send(status ? status.system_exit_status.to_s : "timeout")
          rescue ex
            result.send("#{ex.class.name}:#{ex.message}")
          end
        end
        value = result.receive
        thread.join
        {value == "37", details(result: value)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_duplicate_handle_defers_kill_on_close_until_last_handle") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      duplicate = LibC::HANDLE.null
      begin
        duplicate = duplicate_native_handle(job.probe_native_handle)
        child = job.spawn(self_exe, ["--child", "sleep", "2400"])
        job.close
        alive_with_duplicate = child.handle.alive?
        LibC.CloseHandle(duplicate)
        duplicate = LibC::HANDLE.null
        died_after_last = child.handle.wait(2.seconds)
        {alive_with_duplicate && died_after_last,
         details(alive_with_duplicate: alive_with_duplicate, died_after_last_handle: died_after_last)}
      ensure
        LibC.CloseHandle(duplicate) unless duplicate.null?
        close_child(child)
        close_job(job)
      end
    end

    test("job_kill_sets_child_exit_code_137") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "2200"])
        job.kill
        status = child.wait(3.seconds)
        {status.try(&.system_exit_status) == 137_u32 && job.wait_empty(2.seconds),
         details(exit: status.try(&.system_exit_status), empty: job.empty?)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_kill_terminates_descendant_tree") do
      marker = File.join(workdir, "deep-kill-tree-#{Process.pid}.txt")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "spawn-grandchild", marker])
        raise "grandchild marker missing" unless wait_for_file(marker)
        grandchild = File.read(marker).strip.to_i64
        before = ProcessHandle.observe(grandchild)
        job.kill
        direct = child.wait(3.seconds)
        after = wait_until_dead(grandchild, 3.seconds)
        {before.live? && direct != nil && after.terminated?,
         details(before: before.state, after: after.state, direct_exit: direct.try(&.system_exit_status))}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_reusable_after_terminate_job_object") do
      job = ProcessSupervision.job
      first = nil.as(ProcessSupervision::Child?)
      second = nil.as(ProcessSupervision::Child?)
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "1600"])
        job.kill
        first.wait(2.seconds)
        second = job.spawn(self_exe, ["--child", "exit-code", "0"])
        status = second.wait(2.seconds)
        {status.try(&.success?) == true && !job.closed?, details(reused: status.try(&.success?), closed: job.closed?)}
      ensure
        close_child(first); close_child(second); close_job(job)
      end
    end

    test("job_wait_empty_natural_exit") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "180"])
        before = job.wait_empty(20.milliseconds)
        after = job.wait_empty(2.seconds)
        status = child.wait(2.seconds)
        {(!before) && after && status.try(&.success?) == true, details(short: before, long: after)}
      ensure
        close_child(child); close_job(job)
      end
    end

    test("job_wait_empty_from_raw_thread") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "180"])
        outcome = "unset"
        thread = Thread.new do
          begin
            outcome = job.wait_empty(3.seconds).to_s
          rescue ex
            outcome = "#{ex.class.name}:#{ex.message}"
          end
        end
        thread.join
        status = child.wait(2.seconds)
        {outcome == "true" && status.try(&.success?) == true, details(outcome: outcome)}
      ensure
        close_child(child); close_job(job)
      end
    end

    test("job_concurrent_close_is_idempotent") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 4_u32))
      outcomes = Array(String).new(8, "")
      threads = Array(Thread).new(8) do |i|
        Thread.new do
          begin
            job.close
            outcomes[i] = "ok"
          rescue ex
            outcomes[i] = "#{ex.class.name}:#{ex.message}"
          end
        end
      end
      threads.each(&.join)
      {job.closed? && outcomes.all?(&.==("ok")), details(outcomes: outcomes.join(","))}
    ensure
      close_job(job)
    end

    test("job_concurrent_spawn_16_children") do
      job = ProcessSupervision.job
      children = [] of ProcessSupervision::Child
      lock = Thread::Mutex.new
      errors = [] of String
      threads = Array(Thread).new(16) do |i|
        Thread.new do
          begin
            c = job.spawn(self_exe, ["--child", "exit-code", (i % 3).to_s])
            lock.synchronize { children << c }
          rescue ex
            lock.synchronize { errors << "#{i}:#{ex.class.name}:#{ex.message}" }
          end
        end
      end
      threads.each(&.join)
      statuses = children.map { |c| c.wait(4.seconds) }
      ok = errors.empty? && children.size == 16 && statuses.none?(&.nil?) && job.wait_empty(3.seconds)
      {ok, details(children: children.size, errors: errors.join(" | "), exits: statuses.map { |s| s.try(&.system_exit_status) }.join(","))}
    ensure
      children.try &.each { |c| close_child(c) }
      close_job(job)
    end

    test("active_process_limit_slot_reusable_after_exit") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 1_u32))
      first = nil.as(ProcessSupervision::Child?)
      third = nil.as(ProcessSupervision::Child?)
      rejected = false
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "350"])
        begin
          tmp = job.spawn(self_exe, ["--child", "exit-code", "0"])
          close_child(tmp)
        rescue ProcessSupervision::Error::Native
          rejected = true
        end
        first.wait(2.seconds)
        first.close
        third = job.spawn(self_exe, ["--child", "exit-code", "0"])
        status = third.wait(2.seconds)
        {rejected && status.try(&.success?) == true, details(rejected_while_full: rejected, reused_after_exit: status.try(&.success?))}
      ensure
        close_child(first); close_child(third); close_job(job)
      end
    end

    test("job_limit_validation_complete_invalid_matrix") do
      rejected = [] of String
      cases = {
        "job_memory_zero"       => ProcessSupervision::Windows::Job::Limits.new(job_memory: 0_u64),
        "process_memory_zero"   => ProcessSupervision::Windows::Job::Limits.new(process_memory: 0_u64),
        "active_zero"           => ProcessSupervision::Windows::Job::Limits.new(active_processes: 0_u32),
        "job_time_zero"         => ProcessSupervision::Windows::Job::Limits.new(job_user_time: Time::Span.zero),
        "job_time_negative"     => ProcessSupervision::Windows::Job::Limits.new(job_user_time: -1.millisecond),
        "process_time_zero"     => ProcessSupervision::Windows::Job::Limits.new(process_user_time: Time::Span.zero),
        "process_time_negative" => ProcessSupervision::Windows::Job::Limits.new(process_user_time: -1.millisecond),
        "cpu_zero"              => ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 0.0),
        "cpu_too_small"         => ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 0.001),
        "cpu_negative"          => ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: -1.0),
        "cpu_over"              => ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 100.01),
      }
      cases.each do |name, limits|
        begin
          ProcessSupervision.job(limits).close
        rescue ArgumentError
          rejected << name
        end
      end
      {rejected.size == cases.size, details(rejected: rejected.join(","), expected: cases.size)}
    end

    test("job_priority_idle_applied_to_child") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::Idle, "idle")
    end

    test("job_priority_below_normal_applied_to_child") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::BelowNormal, "below-normal")
    end

    test("job_priority_normal_applied_to_child") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::Normal, "normal")
    end

    test("limit_event_snapshot_stable_across_reads") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 1_u32))
      first = nil.as(ProcessSupervision::Child?)
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "380"])
        begin
          tmp = job.spawn(self_exe, ["--child", "sleep", "80"])
          close_child(tmp)
        rescue ProcessSupervision::Error::Native
        end
        event = wait_for_limit_kind(job, ProcessSupervision::Windows::Job::Limit::Event::Kind::ActiveProcessLimit, 2.seconds)
        a = job.limit_events
        b = job.limit_events
        {event != nil && a == b && !a.same?(b), details(size: a.size, equal: a == b, distinct_arrays: !a.same?(b))}
      ensure
        close_child(first); close_job(job)
      end
    end

    test("raw_completion_multiple_children_new_exit_zero_messages") do
      job = ProcessSupervision.job
      port = LibC.CreateIoCompletionPort(INVALID_HANDLE_VALUE, LibC::HANDLE.null, Pointer(LibC::ULong).null, 1_u32)
      children = [] of ProcessSupervision::Child
      begin
        associate = LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT.new(completionKey: Pointer(Void).new(0x55_u64), completionPort: port)
        raise "associate failed" if LibC.SetInformationJobObject(job.probe_native_handle,
                                      LibC::JOBOBJECTINFOCLASS::AssociateCompletionPortInformation, pointerof(associate).as(Void*),
                                      sizeof(LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT).to_u32) == 0
        4.times { children << job.spawn(self_exe, ["--child", "sleep", "120"]) }
        children.each { |c| c.wait(3.seconds) }
        messages = [] of UInt32
        deadline = Time.instant + 3.seconds
        until Time.instant >= deadline || messages.count(JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO) >= 1
          entry = LibC::OVERLAPPED_ENTRY.new
          removed = LibC::ULong.new(0)
          if LibC.GetQueuedCompletionStatusEx(port, pointerof(entry), 1, pointerof(removed), 100_u32, 0) != 0 && removed > 0
            messages << entry.dwNumberOfBytesTransferred
          end
        end
        {messages.count(JOB_OBJECT_MSG_NEW_PROCESS) >= 4 && messages.count(JOB_OBJECT_MSG_EXIT_PROCESS) >= 4 && messages.includes?(JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO),
         details(messages: messages.join(","), new_count: messages.count(JOB_OBJECT_MSG_NEW_PROCESS), exit_count: messages.count(JOB_OBJECT_MSG_EXIT_PROCESS))}
      ensure
        children.each { |c| close_child(c) }
        LibC.CloseHandle(port) unless port.null?
        close_job(job)
      end
    end

    test("job_breakaway_query_modify_set_native_behavior") do
      marker = File.join(workdir, "breakaway-query-modify-#{Process.pid}.json")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      escaped = nil.as(ProcessHandle?)
      begin
        info = query_extended(job)
        info.basicLimitInformation.limitFlags = info.basicLimitInformation.limitFlags | JOB_OBJECT_LIMIT_BREAKAWAY_OK
        rc = LibC.SetInformationJobObject(job.probe_native_handle, LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32)
        raise "set breakaway failed: #{LibC.GetLastError}" if rc == 0
        configured = (query_extended(job).basicLimitInformation.limitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK) != 0
        child = job.spawn(self_exe, ["--child", "raw-breakaway-attempt", marker])
        status = child.wait(3.seconds)
        payload = JSON.parse(File.read(marker))
        success = payload["success"].as_bool
        native_error = payload["error"].as_i.to_u32
        escaped_pid = payload["pid"].as_i64
        in_inner = nil.as(Bool?)
        if success && escaped_pid > 0
          escaped = ProcessHandle.open(escaped_pid)
          in_inner = escaped.as(ProcessHandle::Windows).probe_is_in_job(job.probe_native_handle)
        end
        # CREATE_BREAKAWAY_FROM_JOB may still be denied by a job higher in the
        # caller's hierarchy. Record that native policy boundary instead of
        # treating it as a shard configuration failure.
        behavior_valid = if success
                           escaped != nil && in_inner == false
                         else
                           native_error == 5_u32
                         end
        {status.try(&.success?) == true && configured && behavior_valid,
         details(configured: configured, success: success, error: native_error, pid: escaped_pid, in_inner_job: in_inner,
           parent_in_job: parent_in_job?, classification: success ? "escaped" : "access_denied_by_job_chain")}
      ensure
        begin
          escaped.try(&.kill) rescue nil
          escaped.try(&.wait(2.seconds)) rescue nil
          escaped.try(&.close) rescue nil
        end
        close_child(child)
        close_job(job)
      end
    end

    test("job_no_limits_has_no_limit_events") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "exit-code", "0"])
        child.wait(2.seconds)
        {job.limit_events.empty?, details(events: job.limit_events.size)}
      ensure
        close_child(child); close_job(job)
      end
    end

    test("spawn_invalid_parent_standard_handles_fall_back_to_nul") do
      marker = File.join(workdir, "std-fallback-#{Process.pid}.json")
      helper = Process.new(self_exe, ["--child", "std-fallback-controller", marker])
      reaped = false
      begin
        status = helper.wait
        reaped = true
        payload = JSON.parse(File.read(marker))
        ok = status.success? && payload["spawned"].as_s == "true" &&
             payload["stdin_valid"].as_s == "true" && payload["stdout_valid"].as_s == "true" && payload["stderr_valid"].as_s == "true"
        {ok, details(payload: payload.to_json)}
      ensure
        cleanup(helper, reaped)
      end
    end

    test("spawn_reserved_drive_environment_entries_preserved") do
      parent_reserved = raw_environment_entries.select(&.starts_with?("="))
      marker = File.join(workdir, "reserved-env-#{Process.pid}.json")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "env-block-dump", marker])
        status = child.wait(3.seconds)
        child_entries = JSON.parse(File.read(marker))["entries"].as_a.map(&.as_s).select(&.starts_with?("="))
        missing = parent_reserved - child_entries
        {status.try(&.success?) == true && missing.empty?, details(parent_reserved: parent_reserved.size, child_reserved: child_entries.size, missing: missing.join("|"))}
      ensure
        close_child(child); close_job(job)
      end
    end

    test("spawn_environment_block_sorted_case_insensitively") do
      marker = File.join(workdir, "env-sort-#{Process.pid}.json")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "env-block-dump", marker], clear_env: true,
          env: {"zProbe" => "1", "Aprobe" => "2", "mProbe" => "3"})
        status = child.wait(3.seconds)
        entries = JSON.parse(File.read(marker))["entries"].as_a.map(&.as_s)
        selected = entries.select { |e| e.downcase.starts_with?("aprobe=") || e.downcase.starts_with?("mprobe=") || e.downcase.starts_with?("zprobe=") }
        {status.try(&.success?) == true && selected.map(&.split('=', 2)[0].downcase) == %w(aprobe mprobe zprobe), details(selected: selected.join("|"))}
      ensure
        close_child(child); close_job(job)
      end
    end

    test("spawn_long_command_line_24k_roundtrip") do
      marker = File.join(workdir, "long-argv-#{Process.pid}.json")
      value = "x" * 24_000
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "args", marker, value])
        status = child.wait(5.seconds)
        actual = JSON.parse(File.read(marker))["args"].as_a[0].as_s
        {status.try(&.success?) == true && actual == value, details(length: actual.size)}
      ensure
        close_child(child); close_job(job)
      end
    end

    test("spawn_oversized_command_line_failure_rolls_back") do
      job = ProcessSupervision.job
      failed = false
      begin
        begin
          c = job.spawn(self_exe, ["--child", "args", File.join(workdir, "too-long.json"), "x" * 40_000])
          close_child(c)
        rescue ProcessSupervision::Error::Native
          failed = true
        end
        child = job.spawn(self_exe, ["--child", "exit-code", "0"])
        status = child.wait(2.seconds)
        close_child(child)
        {failed && status.try(&.success?) == true, details(oversized_rejected: failed, reusable: status.try(&.success?))}
      ensure
        close_job(job)
      end
    end

    test("spawn_file_as_chdir_failure_rolls_back") do
      path = File.join(workdir, "not-a-dir-#{Process.pid}.txt")
      File.write(path, "x")
      job = ProcessSupervision.job
      failed = false
      begin
        begin
          c = job.spawn(self_exe, ["--child", "exit-code", "0"], chdir: path)
          close_child(c)
        rescue ProcessSupervision::Error::Native
          failed = true
        end
        child = job.spawn(self_exe, ["--child", "exit-code", "0"])
        status = child.wait(2.seconds)
        close_child(child)
        {failed && status.try(&.success?) == true, details(file_cwd_rejected: failed, reusable: status.try(&.success?))}
      ensure
        close_job(job)
        File.delete(path) rescue nil
      end
    end

    test("job_accounting_persists_after_children_exit") do
      job = ProcessSupervision.job
      children = [] of ProcessSupervision::Child
      begin
        3.times { |i| children << job.spawn(self_exe, ["--child", "exit-code", i.to_s]) }
        children.each { |c| c.wait(3.seconds) }
        acc = job.accounting
        {acc.active_processes == 0 && acc.total_processes >= 3,
         details(active: acc.active_processes, total: acc.total_processes, terminated: acc.terminated_processes)}
      ensure
        children.each { |c| close_child(c) }; close_job(job)
      end
    end
  end

  def self.run_completion_matrix : Nil
    test("job_capability_metadata_exact") do
      job = ProcessSupervision.job
      begin
        ok = job.mechanism == ProcessSupervision::Mechanism::JobObject && job.kill_on_close? && !job.soft_termination? && !job.closed?
        {ok, details(mechanism: job.mechanism, kill_on_close: job.kill_on_close?, soft_termination: job.soft_termination?, closed: job.closed?)}
      ensure
        close_job(job)
      end
    end

    test("job_shutdown_hard_tier_report_is_not_escalated") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "3000"])
        report = job.shutdown(grace: 5.milliseconds, kill_after: 3.seconds, close: false)
        status = child.wait(2.seconds)
        ok = report.kill_requested? && !report.terminate_requested? && !report.escalated? && report.drained? && !report.closed? && !job.closed? && status != nil
        {ok, details(kill: report.kill_requested?, terminate: report.terminate_requested?, escalated: report.escalated?, drained: report.drained?, report_closed: report.closed?, owner_closed: job.closed?)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("windows_exit_status_still_active_259_is_preserved") do
      child = Process.new(self_exe, ["--child", "exit-u32", "259"])
      status = child.wait
      child.close
      {status.system_exit_status == 259_u32 && status.exit_reason.normal?, details(system_exit_status: status.system_exit_status, exit_reason: status.exit_reason)}
    end

    test("windows_exit_status_u32_max_is_preserved_as_unknown") do
      child = Process.new(self_exe, ["--child", "exit-u32", UInt32::MAX.to_s])
      status = child.wait
      child.close
      {status.system_exit_status == UInt32::MAX && status.exit_reason.unknown?, details(system_exit_status: status.system_exit_status, exit_reason: status.exit_reason)}
    end

    test("windows_access_violation_status_maps_to_access_violation") do
      child = Process.new(self_exe, ["--child", "exit-u32", "3221225477"])
      status = child.wait
      child.close
      {status.system_exit_status == 0xc0000005_u32 && status.exit_reason.access_violation?, details(system_exit_status: status.system_exit_status.to_s(16), exit_reason: status.exit_reason)}
    end

    test("raw_job_handle_is_not_signaled_merely_when_naturally_empty") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "exit-code", "0"])
        status = child.wait(2.seconds)
        raise "child did not finish" unless status
        raise "job did not become empty" unless job.wait_empty(2.seconds)
        rc = LibC.WaitForSingleObject(job.probe_native_handle, 0_u32)
        {rc == LibC::WAIT_TIMEOUT, details(wait_result: rc, expected_timeout: LibC::WAIT_TIMEOUT)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("three_level_nested_jobs_inner_close_kills_member_and_outer_survives") do
      outer = ProcessSupervision.job
      middle = ProcessSupervision.job
      inner = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      replacement = nil.as(ProcessSupervision::Child?)
      begin
        child = outer.spawn(self_exe, ["--child", "sleep", "4000"])
        middle.adopt(child.handle)
        inner.adopt(child.handle)
        inner.close
        killed = child.handle.wait(3.seconds)
        replacement = outer.spawn(self_exe, ["--child", "exit-code", "0"])
        replacement_status = replacement.wait(2.seconds)
        {killed && replacement_status.try(&.success?) == true && !outer.closed? && !middle.closed?, details(killed: killed, outer_reused: replacement_status.try(&.success?), outer_closed: outer.closed?, middle_closed: middle.closed?)}
      ensure
        close_child(child)
        close_child(replacement)
        close_job(inner); close_job(middle); close_job(outer)
      end
    end

    test("nested_job_with_ui_restrictions_native_behavior") do
      outer = ProcessSupervision.job
      restricted = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(
        ui_restrictions: ProcessSupervision::Windows::Job::UIRestrictions::Handles))
      child = nil.as(ProcessSupervision::Child?)
      outcome = "none"
      begin
        child = outer.spawn(self_exe, ["--child", "sleep", "2500"])
        ui = query_u32_class(restricted, JOB_BASIC_UI_RESTRICTIONS_CLASS, 1)[0]
        begin
          restricted.adopt(child.handle)
          outcome = "accepted"
        rescue ex
          outcome = "#{ex.class.name}:#{ex.message}"
        end
        windows = child.handle.as(ProcessHandle::Windows)
        in_outer = windows.probe_is_in_job(outer.probe_native_handle)
        in_restricted = windows.probe_is_in_job(restricted.probe_native_handle)
        accepted_valid = outcome == "accepted" && in_outer && in_restricted
        rejected_valid = outcome != "accepted" && in_outer && !in_restricted
        {ui == ProcessSupervision::Windows::Job::UIRestrictions::Handles.value && child.handle.alive? &&
          (accepted_valid || rejected_valid),
         details(outcome: outcome, child_alive: child.handle.alive?, ui_hex: ui.to_s(16),
           in_outer: in_outer, in_restricted: in_restricted,
           classification: accepted_valid ? "accepted_by_native_host" : "rejected_by_native_host")}
      ensure
        close_child(child)
        close_job(restricted)
        close_job(outer)
      end
    end

    test("job_accounting_page_faults_monotonic_after_memory_work") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        before = job.accounting
        marker = File.join(workdir, "pagefault-#{Process.pid}.json")
        child = job.spawn(self_exe, ["--child", "mem-grow", marker, "48"])
        status = child.wait(5.seconds)
        after = job.accounting
        ok = status != nil && after.page_faults >= before.page_faults && after.total_processes >= before.total_processes
        {ok, details(before_faults: before.page_faults, after_faults: after.page_faults, before_total: before.total_processes, after_total: after.total_processes)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("cpu_rate_hard_cap_is_applied_without_losing_containment") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 25.0))
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "cpu-spin", "900"])
        mid = job.accounting
        status = child.wait(5.seconds)
        final = job.accounting
        ok = status.try(&.success?) == true && final.user_time >= mid.user_time && job.wait_empty(2.seconds)
        {ok, details(mid_user_ms: mid.user_time.total_milliseconds, final_user_ms: final.user_time.total_milliseconds, note: "configuration is exact; scheduling magnitude is recorded but not asserted because host load/CPU topology varies")}
      ensure
        close_child(child)
        close_job(job)
      end
    end
  end

  # Revision-6 matrix helpers. Each caller below has a literal case name so the
  # handback can localize a failure to one exact parameter instead of hiding a
  # broad matrix behind one aggregate result.
  def self.r6_exit_u32_case(code : UInt32)
    child = Process.new(self_exe, ["--child", "exit-u32", code.to_s])
    reaped = false
    begin
      status = child.wait
      reaped = true
      {status.system_exit_status == code,
       details(expected: code, actual: status.system_exit_status, reason: status.exit_reason)}
    ensure
      cleanup(child, reaped)
    end
  end

  def self.r6_supervised_argument_case(value : String, label : String)
    marker = File.join(workdir, "r6-win-arg-#{label}-#{Process.pid}-#{Random.rand(1_000_000)}.json")
    job = ProcessSupervision.job
    child = nil.as(ProcessSupervision::Child?)
    begin
      child = job.spawn(self_exe, ["--child", "args", marker, value])
      status = child.wait(4.seconds)
      raise "argument child timed out" unless status
      payload = JSON.parse(File.read(marker))
      actual = payload["args"].as_a.map(&.as_s)
      {status.success? && actual == [value],
       details(expected_bytes: value.bytesize, actual_bytes: actual.first?.try(&.bytesize), exact: actual == [value])}
    ensure
      close_child(child)
      close_job(job)
    end
  end

  def self.r6_supervised_environment_case(key : String, value : String, label : String, clear_env : Bool = false)
    marker = File.join(workdir, "r6-win-env-#{label}-#{Process.pid}-#{Random.rand(1_000_000)}.json")
    job = ProcessSupervision.job
    child = nil.as(ProcessSupervision::Child?)
    begin
      child = job.spawn(self_exe, ["--child", "env-dump", marker, key], env: {key => value}, clear_env: clear_env)
      status = child.wait(4.seconds)
      raise "environment child timed out" unless status
      payload = JSON.parse(File.read(marker))["values"].as_h
      actual = payload[key]?.try(&.as_s?)
      {status.success? && actual == value,
       details(key: key, expected_bytes: value.bytesize, actual_bytes: actual.try(&.bytesize), clear_env: clear_env)}
    ensure
      close_child(child)
      close_job(job)
    end
  end

  def self.r6_wait_timeout_case(timeout_ms : Int32)
    child = Process.new(self_exe, ["--child", "sleep", "180"])
    handle = nil.as(ProcessHandle?)
    reaped = false
    begin
      handle = ProcessHandle.open(child.pid)
      started = Time.instant
      first = handle.wait(timeout_ms.milliseconds)
      elapsed = Time.instant - started
      completion = handle.wait(2.seconds)
      status = child.wait
      reaped = true
      {(!first) && completion && status.success? && elapsed < 500.milliseconds,
       details(timeout_ms: timeout_ms, first: first, completion: completion,
         elapsed_ms: elapsed.total_milliseconds, exit: status.system_exit_status)}
    ensure
      handle.try &.close
      cleanup(child, reaped)
    end
  end

  def self.r6_fiber_wait_fanout_case(count : Int32)
    child = Process.new(self_exe, ["--child", "sleep", "130"])
    handle = nil.as(ProcessHandle?)
    reaped = false
    begin
      handle = ProcessHandle.open(child.pid)
      results = Channel(Bool).new(count)
      count.times do
        spawn do
          begin
            results.send(handle.not_nil!.wait(3.seconds))
          rescue
            results.send(false)
          end
        end
      end
      values = Array(Bool).new(count) { results.receive }
      status = child.wait
      reaped = true
      {values.all? && status.success?, details(waiters: count, completed: values.count(true), exit: status.system_exit_status)}
    ensure
      handle.try &.close
      cleanup(child, reaped)
    end
  end

  def self.r6_thread_wait_fanout_case(count : Int32)
    child = Process.new(self_exe, ["--child", "sleep", "140"])
    handle = nil.as(ProcessHandle?)
    reaped = false
    begin
      handle = ProcessHandle.open(child.pid)
      ready = Atomic(Int32).new(0)
      go = Atomic(Bool).new(false)
      done = Atomic(Int32).new(0)
      # 1 = wait returned true, -1 = wait timed out, -2 = wait raised
      results = ProbeSlots.new(count)
      errors = [] of String
      error_lock = Thread::Mutex.new
      threads = Array(Thread).new(count) do |index|
        Thread.new do
          ready.add(1)
          until go.get
            Thread.yield
          end
          value = begin
            handle.not_nil!.wait(3.seconds) ? 1 : -1
          rescue ex
            error_lock.synchronize { errors << probe_failure_text(ex) }
            -2
          end
          results[index] = value
          done.add(1)
        end
      end
      ready_ok = wait_until(2.seconds) { ready.get == count }
      go.set(true)
      done_ok = wait_until(4.seconds) { done.get == count }
      status = child.wait
      reaped = true
      threads.each(&.join)
      values = results.to_a
      {ready_ok && done_ok && values.all?(&.==(1)) && status.success?,
       details(waiters: count, ready: ready.get, done: done.get, completed: values.count(1),
         false_results: values.count(-1), errors: values.count(-2), exit: status.system_exit_status,
         first_error: errors.first? || "")}
    ensure
      handle.try &.close
      cleanup(child, reaped)
    end
  end

  def self.r6_job_duplicate_handle_case(count : Int32)
    job = ProcessSupervision.job
    child = nil.as(ProcessSupervision::Child?)
    duplicates = [] of LibC::HANDLE
    begin
      count.times { duplicates << duplicate_native_handle(job.probe_native_handle) }
      child = job.spawn(self_exe, ["--child", "sleep", "1500"])
      job.close
      alive_while_duplicated = child.handle.alive?
      duplicates.each { |h| LibC.CloseHandle(h) }
      duplicates.clear
      terminated = child.handle.wait(3.seconds)
      {alive_while_duplicated && terminated,
       details(duplicates: count, alive_before_last_close: alive_while_duplicated, terminated_after_last_close: terminated)}
    ensure
      duplicates.each { |h| LibC.CloseHandle(h) rescue nil }
      close_child(child)
      close_job(job)
    end
  end

  def self.r6_job_churn_case(cycles : Int32, with_events : Bool)
    before = current_handle_count
    cycles.times do
      job = with_events ? ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 4_u32)) : ProcessSupervision.job
      job.close
    end
    GC.collect
    Thread.sleep(120.milliseconds)
    after = current_handle_count
    delta = after.to_i64 - before.to_i64
    {delta.abs <= 8, details(cycles: cycles, with_events: with_events, before: before, after: after, delta: delta)}
  end

  def self.r6_job_memory_config_case(value : UInt64)
    with_job(ProcessSupervision::Windows::Job::Limits.new(job_memory: value)) do |job|
      info = query_extended(job)
      flags = info.basicLimitInformation.limitFlags
      {info.jobMemoryLimit.to_u64 == value && (flags & JOB_OBJECT_LIMIT_JOB_MEMORY) != 0,
       details(expected: value, actual: info.jobMemoryLimit.to_u64, flags_hex: flags.to_s(16))}
    end
  end

  def self.r6_process_memory_config_case(value : UInt64)
    with_job(ProcessSupervision::Windows::Job::Limits.new(process_memory: value)) do |job|
      info = query_extended(job)
      flags = info.basicLimitInformation.limitFlags
      {info.processMemoryLimit.to_u64 == value && (flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY) != 0,
       details(expected: value, actual: info.processMemoryLimit.to_u64, flags_hex: flags.to_s(16))}
    end
  end

  def self.r6_active_process_config_case(value : UInt32)
    with_job(ProcessSupervision::Windows::Job::Limits.new(active_processes: value)) do |job|
      info = query_extended(job)
      flags = info.basicLimitInformation.limitFlags
      {info.basicLimitInformation.activeProcessLimit == value && (flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) != 0,
       details(expected: value, actual: info.basicLimitInformation.activeProcessLimit, flags_hex: flags.to_s(16))}
    end
  end

  def self.r6_job_time_config_case(span : Time::Span, expected_ticks : Int64)
    with_job(ProcessSupervision::Windows::Job::Limits.new(job_user_time: span)) do |job|
      info = query_extended(job)
      flags = info.basicLimitInformation.limitFlags
      {info.basicLimitInformation.perJobUserTimeLimit == expected_ticks && (flags & JOB_OBJECT_LIMIT_JOB_TIME) != 0,
       details(expected_ticks: expected_ticks, actual_ticks: info.basicLimitInformation.perJobUserTimeLimit, flags_hex: flags.to_s(16))}
    end
  end

  def self.r6_process_time_config_case(span : Time::Span, expected_ticks : Int64)
    with_job(ProcessSupervision::Windows::Job::Limits.new(process_user_time: span)) do |job|
      info = query_extended(job)
      flags = info.basicLimitInformation.limitFlags
      {info.basicLimitInformation.perProcessUserTimeLimit == expected_ticks && (flags & JOB_OBJECT_LIMIT_PROCESS_TIME) != 0,
       details(expected_ticks: expected_ticks, actual_ticks: info.basicLimitInformation.perProcessUserTimeLimit, flags_hex: flags.to_s(16))}
    end
  end

  def self.r6_cpu_rate_config_case(percent : Float64, expected_rate : UInt32)
    with_job(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: percent)) do |job|
      values = query_u32_class(job, JOB_CPU_RATE_CONTROL_CLASS, 2)
      flags = values[0]
      rate = values[1]
      {rate == expected_rate && (flags & CPU_RATE_ENABLE) != 0 && (flags & CPU_RATE_HARD_CAP) != 0,
       details(percent: percent, expected_rate: expected_rate, actual_rate: rate, flags_hex: flags.to_s(16))}
    end
  end

  def self.r6_ui_config_case(value : ProcessSupervision::Windows::Job::UIRestrictions)
    with_job(ProcessSupervision::Windows::Job::Limits.new(ui_restrictions: value)) do |job|
      actual = query_u32_class(job, JOB_BASIC_UI_RESTRICTIONS_CLASS, 1)[0]
      {actual == value.value, details(expected_hex: value.value.to_s(16), actual_hex: actual.to_s(16))}
    end
  end

  def self.r6_invalid_limits_case(limits : ProcessSupervision::Windows::Job::Limits)
    job = nil.as(ProcessSupervision::Windows::Job?)
    outcome = "accepted"
    begin
      job = ProcessSupervision.job(limits)
    rescue ArgumentError
      outcome = "argument_error"
    ensure
      close_job(job)
    end
    {outcome == "argument_error", details(outcome: outcome)}
  end

  def self.r6_active_process_enforcement_case(limit : UInt32)
    job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: limit))
    children = [] of ProcessSupervision::Child
    extra = nil.as(ProcessSupervision::Child?)
    outcome = "accepted"
    begin
      limit.to_i.times { children << job.spawn(self_exe, ["--child", "sleep", "900"]) }
      begin
        extra = job.spawn(self_exe, ["--child", "sleep", "900"])
      rescue ex
        outcome = ex.class.name
      end
      active = job.accounting.active_processes
      event = wait_for_limit_kind(job, ProcessSupervision::Windows::Job::Limit::Event::Kind::ActiveProcessLimit, 1.second)
      {extra.nil? && active == limit && event != nil,
       details(limit: limit, active: active, extra: outcome, event: event.try(&.kind))}
    ensure
      close_child(extra)
      children.each { |c| close_child(c) }
      close_job(job)
    end
  end

  def self.r6_memory_enforcement_case(kind : String, limit_mb : Int32)
    bytes = limit_mb.to_u64 * 1024_u64 * 1024_u64
    limits = kind == "job" ? ProcessSupervision::Windows::Job::Limits.new(job_memory: bytes) : ProcessSupervision::Windows::Job::Limits.new(process_memory: bytes)
    event_kind = kind == "job" ? ProcessSupervision::Windows::Job::Limit::Event::Kind::JobMemoryLimit : ProcessSupervision::Windows::Job::Limit::Event::Kind::ProcessMemoryLimit
    marker = File.join(workdir, "r6-win-mem-#{kind}-#{limit_mb}-#{Process.pid}-#{Random.rand(1_000_000)}.json")
    job = ProcessSupervision.job(limits)
    child = nil.as(ProcessSupervision::Child?)
    begin
      child = job.spawn(self_exe, ["--child", "mem-grow", marker, (limit_mb * 3).clamp(16, 384).to_s])
      status = child.wait(7.seconds)
      event = wait_for_limit_kind(job, event_kind, 2.seconds)
      {status != nil && event != nil,
       details(kind: kind, limit_mb: limit_mb, exit: status.try(&.system_exit_status), event: event.try(&.kind))}
    ensure
      close_child(child)
      close_job(job)
    end
  end

  def self.r6_user_time_enforcement_case(kind : String, milliseconds : Int32)
    span = milliseconds.milliseconds
    limits = kind == "job" ? ProcessSupervision::Windows::Job::Limits.new(job_user_time: span) : ProcessSupervision::Windows::Job::Limits.new(process_user_time: span)
    expected_kind = kind == "job" ? ProcessSupervision::Windows::Job::Limit::Event::Kind::EndOfJobTime : ProcessSupervision::Windows::Job::Limit::Event::Kind::EndOfProcessTime
    job = ProcessSupervision.job(limits)
    child = nil.as(ProcessSupervision::Child?)
    begin
      # Windows evaluates job CPU-time limits in a periodic system-wide pass of about 7 s, not when the
      # limit is crossed (native evidence: explore/windows cpu-time + cpu-period). Spin and wait for
      # two periods so enforcement is observed rather than depending on where the tick lands.
      child = job.spawn(self_exe, ["--child", "cpu-spin", "15000"])
      status = child.wait(18.seconds)
      event = wait_for_limit_kind(job, expected_kind, 3.seconds)
      {status != nil && status.try(&.system_exit_status) != 0_u32,
       details(kind: kind, configured_ms: milliseconds, exit: status.try(&.system_exit_status), event: event.try(&.kind))}
    ensure
      close_child(child)
      close_job(job)
    end
  end

  def self.r7_repeated_wait_timeout_case(timeout : Time::Span, count : Int32, child_ms : Int32)
    child = Process.new(self_exe, ["--child", "sleep", child_ms.to_s])
    handle = nil.as(ProcessHandle?)
    reaped = false
    begin
      handle = ProcessHandle.open(child.pid)
      results = [] of Bool
      elapsed = [] of Float64
      count.times do
        started = Time.instant
        results << handle.wait(timeout)
        elapsed << (Time.instant - started).total_milliseconds
      end
      still_live = handle.alive?
      final = handle.wait(3.seconds)
      status = child.wait
      reaped = true
      ceiling = {timeout.total_milliseconds * 8.0 + 100.0, 250.0}.max
      {results.none? && still_live && final && status.success? && elapsed.all? { |ms| ms < ceiling },
       details(timeout_ms: timeout.total_milliseconds, count: count, early_true: results.count(true),
         still_live_after_sequence: still_live, final: final, max_wait_ms: elapsed.max.round(3), ceiling_ms: ceiling.round(3))}
    ensure
      handle.try &.close rescue nil
      child.try { |c| cleanup(c, reaped || false) }
    end
  end

  def self.run_r6_matrix : Nil
    test("r6_exit_u32_00000000") do
      r6_exit_u32_case(0x00000000_u32)
    end

    test("r6_exit_u32_00000001") do
      r6_exit_u32_case(0x00000001_u32)
    end

    test("r6_exit_u32_00000002") do
      r6_exit_u32_case(0x00000002_u32)
    end

    test("r6_exit_u32_00000003") do
      r6_exit_u32_case(0x00000003_u32)
    end

    test("r6_exit_u32_00000007") do
      r6_exit_u32_case(0x00000007_u32)
    end

    test("r6_exit_u32_00000008") do
      r6_exit_u32_case(0x00000008_u32)
    end

    test("r6_exit_u32_0000000f") do
      r6_exit_u32_case(0x0000000f_u32)
    end

    test("r6_exit_u32_0000001f") do
      r6_exit_u32_case(0x0000001f_u32)
    end

    test("r6_exit_u32_00000020") do
      r6_exit_u32_case(0x00000020_u32)
    end

    test("r6_exit_u32_0000002a") do
      r6_exit_u32_case(0x0000002a_u32)
    end

    test("r6_exit_u32_0000003f") do
      r6_exit_u32_case(0x0000003f_u32)
    end

    test("r6_exit_u32_00000040") do
      r6_exit_u32_case(0x00000040_u32)
    end

    test("r6_exit_u32_00000041") do
      r6_exit_u32_case(0x00000041_u32)
    end

    test("r6_exit_u32_00000046") do
      r6_exit_u32_case(0x00000046_u32)
    end

    test("r6_exit_u32_00000049") do
      r6_exit_u32_case(0x00000049_u32)
    end

    test("r6_exit_u32_0000004a") do
      r6_exit_u32_case(0x0000004a_u32)
    end

    test("r6_exit_u32_0000004b") do
      r6_exit_u32_case(0x0000004b_u32)
    end

    test("r6_exit_u32_0000004e") do
      r6_exit_u32_case(0x0000004e_u32)
    end

    test("r6_exit_u32_00000064") do
      r6_exit_u32_case(0x00000064_u32)
    end

    test("r6_exit_u32_0000007d") do
      r6_exit_u32_case(0x0000007d_u32)
    end

    test("r6_exit_u32_0000007e") do
      r6_exit_u32_case(0x0000007e_u32)
    end

    test("r6_exit_u32_0000007f") do
      r6_exit_u32_case(0x0000007f_u32)
    end

    test("r6_exit_u32_00000080") do
      r6_exit_u32_case(0x00000080_u32)
    end

    test("r6_exit_u32_00000089") do
      r6_exit_u32_case(0x00000089_u32)
    end

    test("r6_exit_u32_000000c8") do
      r6_exit_u32_case(0x000000c8_u32)
    end

    test("r6_exit_u32_000000fe") do
      r6_exit_u32_case(0x000000fe_u32)
    end

    test("r6_exit_u32_000000ff") do
      r6_exit_u32_case(0x000000ff_u32)
    end

    test("r6_exit_u32_00000100") do
      r6_exit_u32_case(0x00000100_u32)
    end

    test("r6_exit_u32_00000102") do
      r6_exit_u32_case(0x00000102_u32)
    end

    test("r6_exit_u32_00000103") do
      r6_exit_u32_case(0x00000103_u32)
    end

    test("r6_exit_u32_40000000") do
      r6_exit_u32_case(0x40000000_u32)
    end

    test("r6_exit_u32_7fffffff") do
      r6_exit_u32_case(0x7fffffff_u32)
    end

    test("r6_exit_u32_80000000") do
      r6_exit_u32_case(0x80000000_u32)
    end

    test("r6_exit_u32_c0000005") do
      r6_exit_u32_case(0xc0000005_u32)
    end

    test("r6_exit_u32_c0000017") do
      r6_exit_u32_case(0xc0000017_u32)
    end

    test("r6_exit_u32_c000013a") do
      r6_exit_u32_case(0xc000013a_u32)
    end

    test("r6_exit_u32_c0000409") do
      r6_exit_u32_case(0xc0000409_u32)
    end

    test("r6_exit_u32_ffffffff") do
      r6_exit_u32_case(0xffffffff_u32)
    end

    test("r6_spawn_argument_00") do
      r6_supervised_argument_case("a", "0")
    end

    test("r6_spawn_argument_01") do
      r6_supervised_argument_case("abc", "1")
    end

    test("r6_spawn_argument_02") do
      r6_supervised_argument_case(" ", "2")
    end

    test("r6_spawn_argument_03") do
      r6_supervised_argument_case("  leading", "3")
    end

    test("r6_spawn_argument_04") do
      r6_supervised_argument_case("trailing  ", "4")
    end

    test("r6_spawn_argument_05") do
      r6_supervised_argument_case("both sides", "5")
    end

    test("r6_spawn_argument_06") do
      r6_supervised_argument_case("a b", "6")
    end

    test("r6_spawn_argument_07") do
      r6_supervised_argument_case("a  b", "7")
    end

    test("r6_spawn_argument_08") do
      r6_supervised_argument_case("a\tb", "8")
    end

    test("r6_spawn_argument_09") do
      r6_supervised_argument_case("a\nb", "9")
    end

    test("r6_spawn_argument_10") do
      r6_supervised_argument_case("\t", "10")
    end

    test("r6_spawn_argument_11") do
      r6_supervised_argument_case("\n", "11")
    end

    test("r6_spawn_argument_12") do
      r6_supervised_argument_case("\"", "12")
    end

    test("r6_spawn_argument_13") do
      r6_supervised_argument_case("\"quoted\"", "13")
    end

    test("r6_spawn_argument_14") do
      r6_supervised_argument_case("a\"b", "14")
    end

    test("r6_spawn_argument_15") do
      r6_supervised_argument_case("a\"\"b", "15")
    end

    test("r6_spawn_argument_16") do
      r6_supervised_argument_case("\\", "16")
    end

    test("r6_spawn_argument_17") do
      r6_supervised_argument_case("\\\\", "17")
    end

    test("r6_spawn_argument_18") do
      r6_supervised_argument_case("trailing\\", "18")
    end

    test("r6_spawn_argument_19") do
      r6_supervised_argument_case("trailing\\\\", "19")
    end

    test("r6_spawn_argument_20") do
      r6_supervised_argument_case("\\\"", "20")
    end

    test("r6_spawn_argument_21") do
      r6_supervised_argument_case("\\\\\"", "21")
    end

    test("r6_spawn_argument_22") do
      r6_supervised_argument_case("a\\\"b", "22")
    end

    test("r6_spawn_argument_23") do
      r6_supervised_argument_case("a\\\\\"b", "23")
    end

    test("r6_spawn_argument_24") do
      r6_supervised_argument_case("C:\\path with spaces\\", "24")
    end

    test("r6_spawn_argument_25") do
      r6_supervised_argument_case("C:\\endslash\\", "25")
    end

    test("r6_spawn_argument_26") do
      r6_supervised_argument_case("--flag=value", "26")
    end

    test("r6_spawn_argument_27") do
      r6_supervised_argument_case("--flag=\"quoted value\"", "27")
    end

    test("r6_spawn_argument_28") do
      r6_supervised_argument_case("single'quote", "28")
    end

    test("r6_spawn_argument_29") do
      r6_supervised_argument_case("semi;colon", "29")
    end

    test("r6_spawn_argument_30") do
      r6_supervised_argument_case("amp&ersand", "30")
    end

    test("r6_spawn_argument_31") do
      r6_supervised_argument_case("pipe|char", "31")
    end

    test("r6_spawn_argument_32") do
      r6_supervised_argument_case("caret^char", "32")
    end

    test("r6_spawn_argument_33") do
      r6_supervised_argument_case("percent%char", "33")
    end

    test("r6_spawn_argument_34") do
      r6_supervised_argument_case("bang!char", "34")
    end

    test("r6_spawn_argument_35") do
      r6_supervised_argument_case("paren(value)", "35")
    end

    test("r6_spawn_argument_36") do
      r6_supervised_argument_case("snowman-☃", "36")
    end

    test("r6_spawn_argument_37") do
      r6_supervised_argument_case("emoji-😀", "37")
    end

    test("r6_spawn_argument_38") do
      r6_supervised_argument_case("cjk-日本語", "38")
    end

    test("r6_spawn_argument_39") do
      r6_supervised_argument_case("rtl-مرحبا", "39")
    end

    test("r6_spawn_argument_40") do
      r6_supervised_argument_case("combining-é", "40")
    end

    test("r6_spawn_argument_41") do
      r6_supervised_argument_case("math-∑≈√", "41")
    end

    test("r6_spawn_argument_42") do
      r6_supervised_argument_case("nbsp- -x", "42")
    end

    test("r6_spawn_argument_43") do
      r6_supervised_argument_case("zero-width-​-x", "43")
    end

    test("r6_spawn_argument_44") do
      r6_supervised_argument_case("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "44")
    end

    test("r6_spawn_argument_45") do
      r6_supervised_argument_case("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "45")
    end

    test("r6_spawn_argument_46") do
      r6_supervised_argument_case("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "46")
    end

    test("r6_spawn_argument_47") do
      r6_supervised_argument_case("qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "47")
    end

    test("r6_spawn_argument_48") do
      r6_supervised_argument_case("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr", "48")
    end

    test("r6_spawn_environment_00") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_00", "", "0")
    end

    test("r6_spawn_environment_01") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_01", "x", "1")
    end

    test("r6_spawn_environment_02") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_02", "a b", "2")
    end

    test("r6_spawn_environment_03") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_03", "  spaced  ", "3")
    end

    test("r6_spawn_environment_04") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_04", "a\tb", "4")
    end

    test("r6_spawn_environment_05") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_05", "a\nb", "5")
    end

    test("r6_spawn_environment_06") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_06", "\"quoted\"", "6")
    end

    test("r6_spawn_environment_07") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_07", "\\", "7")
    end

    test("r6_spawn_environment_08") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_08", "C:\\path\\value", "8")
    end

    test("r6_spawn_environment_09") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_09", "100%", "9")
    end

    test("r6_spawn_environment_10") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_10", "a=b", "10")
    end

    test("r6_spawn_environment_11") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_11", "semi;colon", "11")
    end

    test("r6_spawn_environment_12") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_12", "amp&ersand", "12")
    end

    test("r6_spawn_environment_13") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_13", "snowman-☃", "13")
    end

    test("r6_spawn_environment_14") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_14", "emoji-😀", "14")
    end

    test("r6_spawn_environment_15") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_15", "日本語", "15")
    end

    test("r6_spawn_environment_16") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_16", "مرحبا", "16")
    end

    test("r6_spawn_environment_17") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_17", "é", "17")
    end

    test("r6_spawn_environment_18") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_18", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "18")
    end

    test("r6_spawn_environment_19") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_19", "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", "19")
    end

    test("r6_spawn_environment_20") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_20", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "20")
    end

    test("r6_spawn_environment_21") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_ENV_21", "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "21")
    end

    test("r6_spawn_clear_environment_00") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_CLEAR_00", "x", "c0", true)
    end

    test("r6_spawn_clear_environment_01") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_CLEAR_01", "", "c1", true)
    end

    test("r6_spawn_clear_environment_02") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_CLEAR_02", "unicode-😀", "c2", true)
    end

    test("r6_spawn_clear_environment_03") do
      r6_supervised_environment_case("PROCESS_PROBE_R6_CLEAR_03", "value with spaces", "c3", true)
    end

    test("r6_wait_timeout_000ms") do
      r6_wait_timeout_case(0)
    end

    test("r6_wait_timeout_001ms") do
      r6_wait_timeout_case(1)
    end

    test("r6_wait_timeout_002ms") do
      r6_wait_timeout_case(2)
    end

    test("r6_wait_timeout_005ms") do
      r6_wait_timeout_case(5)
    end

    test("r6_wait_timeout_010ms") do
      r6_wait_timeout_case(10)
    end

    test("r6_wait_timeout_020ms") do
      r6_wait_timeout_case(20)
    end

    test("r6_wait_timeout_040ms") do
      r6_wait_timeout_case(40)
    end

    test("r6_wait_timeout_080ms") do
      r6_wait_timeout_case(80)
    end

    test("r6_fiber_wait_fanout_01") do
      r6_fiber_wait_fanout_case(1)
    end

    test("r6_fiber_wait_fanout_02") do
      r6_fiber_wait_fanout_case(2)
    end

    test("r6_fiber_wait_fanout_04") do
      r6_fiber_wait_fanout_case(4)
    end

    test("r6_fiber_wait_fanout_08") do
      r6_fiber_wait_fanout_case(8)
    end

    test("r6_fiber_wait_fanout_16") do
      r6_fiber_wait_fanout_case(16)
    end

    test("r6_fiber_wait_fanout_32") do
      r6_fiber_wait_fanout_case(32)
    end

    test("r6_thread_wait_fanout_01") do
      r6_thread_wait_fanout_case(1)
    end

    test("r6_thread_wait_fanout_02") do
      r6_thread_wait_fanout_case(2)
    end

    test("r6_thread_wait_fanout_04") do
      r6_thread_wait_fanout_case(4)
    end

    test("r6_thread_wait_fanout_08") do
      r6_thread_wait_fanout_case(8)
    end

    test("r6_thread_wait_fanout_16") do
      r6_thread_wait_fanout_case(16)
    end

    test("r6_job_duplicate_handles_01") do
      r6_job_duplicate_handle_case(1)
    end

    test("r6_job_duplicate_handles_02") do
      r6_job_duplicate_handle_case(2)
    end

    test("r6_job_duplicate_handles_04") do
      r6_job_duplicate_handle_case(4)
    end

    test("r6_job_duplicate_handles_08") do
      r6_job_duplicate_handle_case(8)
    end

    test("r6_job_duplicate_handles_16") do
      r6_job_duplicate_handle_case(16)
    end

    test("r6_job_churn_plain_001") do
      r6_job_churn_case(1, false)
    end

    test("r6_job_churn_events_001") do
      r6_job_churn_case(1, true)
    end

    test("r6_job_churn_plain_005") do
      r6_job_churn_case(5, false)
    end

    test("r6_job_churn_events_005") do
      r6_job_churn_case(5, true)
    end

    test("r6_job_churn_plain_025") do
      r6_job_churn_case(25, false)
    end

    test("r6_job_churn_events_025") do
      r6_job_churn_case(25, true)
    end

    test("r6_job_churn_plain_075") do
      r6_job_churn_case(75, false)
    end

    test("r6_job_churn_events_075") do
      r6_job_churn_case(75, true)
    end

    test("r6_job_churn_plain_150") do
      r6_job_churn_case(150, false)
    end

    test("r6_job_churn_events_150") do
      r6_job_churn_case(150, true)
    end

    test("r6_job_memory_config_4096") do
      r6_job_memory_config_case(4096_u64)
    end

    test("r6_process_memory_config_4096") do
      r6_process_memory_config_case(4096_u64)
    end

    test("r6_job_memory_config_65536") do
      r6_job_memory_config_case(65536_u64)
    end

    test("r6_process_memory_config_65536") do
      r6_process_memory_config_case(65536_u64)
    end

    test("r6_job_memory_config_1048576") do
      r6_job_memory_config_case(1048576_u64)
    end

    test("r6_process_memory_config_1048576") do
      r6_process_memory_config_case(1048576_u64)
    end

    test("r6_job_memory_config_16777216") do
      r6_job_memory_config_case(16777216_u64)
    end

    test("r6_process_memory_config_16777216") do
      r6_process_memory_config_case(16777216_u64)
    end

    test("r6_job_memory_config_67108864") do
      r6_job_memory_config_case(67108864_u64)
    end

    test("r6_process_memory_config_67108864") do
      r6_process_memory_config_case(67108864_u64)
    end

    test("r6_job_memory_config_536870912") do
      r6_job_memory_config_case(536870912_u64)
    end

    test("r6_process_memory_config_536870912") do
      r6_process_memory_config_case(536870912_u64)
    end

    test("r6_job_memory_config_4294967296") do
      r6_job_memory_config_case(4294967296_u64)
    end

    test("r6_process_memory_config_4294967296") do
      r6_process_memory_config_case(4294967296_u64)
    end

    test("r6_active_process_config_001") do
      r6_active_process_config_case(1_u32)
    end

    test("r6_active_process_config_002") do
      r6_active_process_config_case(2_u32)
    end

    test("r6_active_process_config_003") do
      r6_active_process_config_case(3_u32)
    end

    test("r6_active_process_config_004") do
      r6_active_process_config_case(4_u32)
    end

    test("r6_active_process_config_008") do
      r6_active_process_config_case(8_u32)
    end

    test("r6_active_process_config_016") do
      r6_active_process_config_case(16_u32)
    end

    test("r6_active_process_config_064") do
      r6_active_process_config_case(64_u32)
    end

    test("r6_active_process_config_256") do
      r6_active_process_config_case(256_u32)
    end

    test("r6_job_time_config_1us") do
      r6_job_time_config_case(Time::Span.new(nanoseconds: 1000_i64), 10_i64)
    end

    test("r6_process_time_config_1us") do
      r6_process_time_config_case(Time::Span.new(nanoseconds: 1000_i64), 10_i64)
    end

    test("r6_job_time_config_10us") do
      r6_job_time_config_case(Time::Span.new(nanoseconds: 10000_i64), 100_i64)
    end

    test("r6_process_time_config_10us") do
      r6_process_time_config_case(Time::Span.new(nanoseconds: 10000_i64), 100_i64)
    end

    test("r6_job_time_config_100us") do
      r6_job_time_config_case(Time::Span.new(nanoseconds: 100000_i64), 1000_i64)
    end

    test("r6_process_time_config_100us") do
      r6_process_time_config_case(Time::Span.new(nanoseconds: 100000_i64), 1000_i64)
    end

    test("r6_job_time_config_1ms") do
      r6_job_time_config_case(Time::Span.new(nanoseconds: 1000000_i64), 10000_i64)
    end

    test("r6_process_time_config_1ms") do
      r6_process_time_config_case(Time::Span.new(nanoseconds: 1000000_i64), 10000_i64)
    end

    test("r6_job_time_config_10ms") do
      r6_job_time_config_case(Time::Span.new(nanoseconds: 10000000_i64), 100000_i64)
    end

    test("r6_process_time_config_10ms") do
      r6_process_time_config_case(Time::Span.new(nanoseconds: 10000000_i64), 100000_i64)
    end

    test("r6_job_time_config_100ms") do
      r6_job_time_config_case(Time::Span.new(nanoseconds: 100000000_i64), 1000000_i64)
    end

    test("r6_process_time_config_100ms") do
      r6_process_time_config_case(Time::Span.new(nanoseconds: 100000000_i64), 1000000_i64)
    end

    test("r6_job_time_config_1s") do
      r6_job_time_config_case(Time::Span.new(nanoseconds: 1000000000_i64), 10000000_i64)
    end

    test("r6_process_time_config_1s") do
      r6_process_time_config_case(Time::Span.new(nanoseconds: 1000000000_i64), 10000000_i64)
    end

    test("r6_cpu_rate_config_0_01") do
      r6_cpu_rate_config_case(0.01, 1_u32)
    end

    test("r6_cpu_rate_config_0_1") do
      r6_cpu_rate_config_case(0.1, 10_u32)
    end

    test("r6_cpu_rate_config_0_5") do
      r6_cpu_rate_config_case(0.5, 50_u32)
    end

    test("r6_cpu_rate_config_1_0") do
      r6_cpu_rate_config_case(1.0, 100_u32)
    end

    test("r6_cpu_rate_config_2_5") do
      r6_cpu_rate_config_case(2.5, 250_u32)
    end

    test("r6_cpu_rate_config_10_0") do
      r6_cpu_rate_config_case(10.0, 1000_u32)
    end

    test("r6_cpu_rate_config_12_34") do
      r6_cpu_rate_config_case(12.34, 1234_u32)
    end

    test("r6_cpu_rate_config_25_0") do
      r6_cpu_rate_config_case(25.0, 2500_u32)
    end

    test("r6_cpu_rate_config_33_33") do
      r6_cpu_rate_config_case(33.33, 3333_u32)
    end

    test("r6_cpu_rate_config_50_0") do
      r6_cpu_rate_config_case(50.0, 5000_u32)
    end

    test("r6_cpu_rate_config_66_67") do
      r6_cpu_rate_config_case(66.67, 6667_u32)
    end

    test("r6_cpu_rate_config_75_0") do
      r6_cpu_rate_config_case(75.0, 7500_u32)
    end

    test("r6_cpu_rate_config_99_99") do
      r6_cpu_rate_config_case(99.99, 9999_u32)
    end

    test("r6_cpu_rate_config_100_0") do
      r6_cpu_rate_config_case(100.0, 10000_u32)
    end

    test("r6_ui_restriction_handles") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::Handles)
    end

    test("r6_ui_restriction_read_clipboard") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::ReadClipboard)
    end

    test("r6_ui_restriction_write_clipboard") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::WriteClipboard)
    end

    test("r6_ui_restriction_system_parameters") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::SystemParameters)
    end

    test("r6_ui_restriction_display_settings") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::DisplaySettings)
    end

    test("r6_ui_restriction_global_atoms") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::GlobalAtoms)
    end

    test("r6_ui_restriction_desktop") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::Desktop)
    end

    test("r6_ui_restriction_exit_windows") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::ExitWindows)
    end

    test("r6_ui_restriction_combo_clipboard") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::ReadClipboard | ProcessSupervision::Windows::Job::UIRestrictions::WriteClipboard)
    end

    test("r6_ui_restriction_combo_desktop_handles") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::Desktop | ProcessSupervision::Windows::Job::UIRestrictions::Handles)
    end

    test("r6_ui_restriction_combo_display_system") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::DisplaySettings | ProcessSupervision::Windows::Job::UIRestrictions::SystemParameters)
    end

    test("r6_ui_restriction_combo_atoms_handles") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::GlobalAtoms | ProcessSupervision::Windows::Job::UIRestrictions::Handles)
    end

    test("r6_ui_restriction_combo_all") do
      r6_ui_config_case(ProcessSupervision::Windows::Job::UIRestrictions::Handles | ProcessSupervision::Windows::Job::UIRestrictions::ReadClipboard | ProcessSupervision::Windows::Job::UIRestrictions::WriteClipboard | ProcessSupervision::Windows::Job::UIRestrictions::SystemParameters | ProcessSupervision::Windows::Job::UIRestrictions::DisplaySettings | ProcessSupervision::Windows::Job::UIRestrictions::GlobalAtoms | ProcessSupervision::Windows::Job::UIRestrictions::Desktop | ProcessSupervision::Windows::Job::UIRestrictions::ExitWindows)
    end

    test("r6_priority_applied_idle") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::Idle, "r6_idle")
    end

    test("r6_priority_applied_below_normal") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::BelowNormal, "r6_below_normal")
    end

    test("r6_priority_applied_normal") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::Normal, "r6_normal")
    end

    test("r6_priority_applied_above_normal") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::AboveNormal, "r6_above_normal")
    end

    test("r6_priority_applied_high") do
      probe_priority_applied(ProcessSupervision::Windows::Job::PriorityClass::High, "r6_high")
    end

    test("r6_invalid_limits_job_memory_zero") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(job_memory: 0_u64))
    end

    test("r6_invalid_limits_process_memory_zero") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(process_memory: 0_u64))
    end

    test("r6_invalid_limits_active_process_zero") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(active_processes: 0_u32))
    end

    test("r6_invalid_limits_job_time_zero") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(job_user_time: Time::Span.zero))
    end

    test("r6_invalid_limits_job_time_negative") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(job_user_time: -1.millisecond))
    end

    test("r6_invalid_limits_process_time_zero") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(process_user_time: Time::Span.zero))
    end

    test("r6_invalid_limits_process_time_negative") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(process_user_time: -1.millisecond))
    end

    test("r6_invalid_limits_cpu_negative") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: -1.0))
    end

    test("r6_invalid_limits_cpu_zero") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 0.0))
    end

    test("r6_invalid_limits_cpu_sub_quantum") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 0.0001))
    end

    test("r6_invalid_limits_cpu_over_100") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: 100.01))
    end

    test("r6_invalid_limits_cpu_nan") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: Float64::NAN))
    end

    test("r6_invalid_limits_cpu_infinity") do
      r6_invalid_limits_case(ProcessSupervision::Windows::Job::Limits.new(cpu_rate_percent: Float64::INFINITY))
    end

    test("r6_active_process_enforcement_01") do
      r6_active_process_enforcement_case(1_u32)
    end

    test("r6_active_process_enforcement_02") do
      r6_active_process_enforcement_case(2_u32)
    end

    test("r6_active_process_enforcement_04") do
      r6_active_process_enforcement_case(4_u32)
    end

    test("r6_active_process_enforcement_08") do
      r6_active_process_enforcement_case(8_u32)
    end

    test("r6_job_memory_enforcement_032mb") do
      r6_memory_enforcement_case("job", 32)
    end

    test("r6_job_memory_enforcement_064mb") do
      r6_memory_enforcement_case("job", 64)
    end

    test("r6_job_memory_enforcement_128mb") do
      r6_memory_enforcement_case("job", 128)
    end

    test("r6_process_memory_enforcement_032mb") do
      r6_memory_enforcement_case("process", 32)
    end

    test("r6_process_memory_enforcement_064mb") do
      r6_memory_enforcement_case("process", 64)
    end

    test("r6_process_memory_enforcement_128mb") do
      r6_memory_enforcement_case("process", 128)
    end

    test("r6_job_user_time_enforcement_050ms") do
      r6_user_time_enforcement_case("job", 50)
    end

    test("r6_job_user_time_enforcement_150ms") do
      r6_user_time_enforcement_case("job", 150)
    end

    test("r6_job_user_time_enforcement_300ms") do
      r6_user_time_enforcement_case("job", 300)
    end

    test("r6_process_user_time_enforcement_050ms") do
      r6_user_time_enforcement_case("process", 50)
    end

    test("r6_process_user_time_enforcement_150ms") do
      r6_user_time_enforcement_case("process", 150)
    end

    test("r6_process_user_time_enforcement_300ms") do
      r6_user_time_enforcement_case("process", 300)
    end
  end

  def self.r9_job_pid_list_active_case(count : Int32)
    job = ProcessSupervision.job
    children = [] of ProcessSupervision::Child
    begin
      count.times { children << job.spawn(self_exe, ["--child", "sleep", "1400"]) }
      result = raw_job_process_ids(job, count + 4)
      expected = children.map(&.pid.to_u64).sort
      observed = result[:ids].sort
      {result[:ok] && result[:assigned] >= count && result[:listed] == count && observed == expected,
       details(count: count, assigned: result[:assigned], listed: result[:listed], expected: expected.join(","), observed: observed.join(","), returned: result[:returned])}
    ensure
      children.each { |child| close_child(child) }
      close_job(job)
    end
  end

  def self.r9_cross_job_handle_isolation_case(count : Int32)
    sentinel_handles = [] of LibC::HANDLE
    jobs = [] of ProcessSupervision::Windows::Job
    children = [] of ProcessSupervision::Child
    lock = Thread::Mutex.new
    failures = [] of String
    threads = [] of ProbeThread
    begin
      count.times do
        event = WindowsProbeNative.CreateEventW(Pointer(LibC::SECURITY_ATTRIBUTES).null, 1, 0, Pointer(UInt16).null)
        raise "CreateEventW failed: #{LibC.GetLastError}" if event.null?
        sentinel_handles << event
        raise "SetHandleInformation failed" if WindowsProbeNative.SetHandleInformation(event, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0
        jobs << ProcessSupervision.job
      end
      all = sentinel_handles.map { |h| h.address.to_u64 }.join(",")
      jobs.each_with_index do |job, i|
        threads << ProbeThread.new("cross-job-#{i}") do
          marker = File.join(workdir, "r9-handle-isolation-#{Process.pid}-#{count}-#{i}.json")
          begin
            child = job.spawn(self_exe, ["--child", "check-handles", marker, all])
            status = child.wait(4.seconds)
            payload = JSON.parse(File.read(marker)).as_h
            lock.synchronize do
              children << child
              failures << "#{i}:exit=#{status.try(&.system_exit_status)} count=#{payload["count"].as_i}" unless status.try(&.success?) == true && payload["count"].as_i == 0
            end
          rescue ex
            lock.synchronize { failures << "#{i}:#{probe_failure_text(ex)}" }
          end
        end
      end
      threads.each(&.join)
      {failures.empty?, details(count: count, failures: failures.join("|"), sentinels: sentinel_handles.size,
        contract: "per-spawn HANDLE_LIST blocks unrelated inheritable handles across concurrent Jobs")}
    ensure
      children.each { |child| close_child(child) }
      jobs.each { |job| close_job(job) }
      sentinel_handles.each { |h| LibC.CloseHandle(h) unless h.null? }
    end
  end

  # Revision-10 regression closure for checkpoint 0008. Keep this separate
  # from the revision-9 source matrix so prior case identities remain stable.
  def self.run_r10_hardening_matrix : Nil
    test("r10_block_scoped_open_preserves_primary_error") do
      payload = run_fault_helper("block-open-first-error")
      result = payload["result"].as_s
      {result.includes?("injected block failure") && !result.includes?("CloseHandle(process)") && !result.includes?("unexpected_success"),
       details(result: result, contract: "caller failure wins over block-scoped owner close failure")}
    end
  end

  # Source-driven revision-9 additions. These are behavior families derived
  # from the uploaded Wine/ReactOS, BuildXL, System Informer, Fs.Processes,
  # CPython, Go, Rust, JDK, Swift Foundation, Apple Libc and win_safesubprocess
  # snapshots. They intentionally target semantics not already represented by
  # the revision-8 parameter matrix.
  def self.run_r9_source_matrix : Nil
    test("r9_spawn_cleanup_preserves_primary_setup_error") do
      payload = run_fault_helper("spawn-cleanup-first-error")
      result = payload["result"].as_s
      {result.includes?("process identity changed before resume") && !result.includes?("injected spawn-cleanup close failure"),
       details(result: result, contract: "primary spawn/setup failure wins over stable-handle cleanup failure")}
    end

    test("r9_job_pid_list_empty") do
      with_job do |job|
        result = raw_job_process_ids(job, 4)
        {result[:ok] && result[:assigned] == 0 && result[:listed] == 0 && result[:ids].empty?,
         details(ok: result[:ok], error: result[:error], returned: result[:returned], assigned: result[:assigned], listed: result[:listed])}
      end
    end

    test("r9_job_pid_list_active_1") do
      r9_job_pid_list_active_case(1)
    end
    test("r9_job_pid_list_active_2") do
      r9_job_pid_list_active_case(2)
    end
    test("r9_job_pid_list_active_4") do
      r9_job_pid_list_active_case(4)
    end
    test("r9_job_pid_list_active_8") do
      r9_job_pid_list_active_case(8)
    end
    test("r9_job_pid_list_active_16") do
      r9_job_pid_list_active_case(16)
    end
    test("r9_job_pid_list_active_32") do
      r9_job_pid_list_active_case(32)
    end

    test("r9_job_pid_list_dead_child_excluded_accounting_persists") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "exit-code", "0"])
        pid = child.pid.to_u64
        child.wait(2.seconds)
        wait_until(1.second) { job.accounting.active_processes == 0 }
        list = raw_job_process_ids(job, 4)
        accounting = job.accounting
        {list[:ok] && !list[:ids].includes?(pid) && accounting.total_processes >= 1 && accounting.active_processes == 0,
         details(pid: pid, assigned: list[:assigned], listed: list[:listed], ids: list[:ids].join(","), total_processes: accounting.total_processes, active_processes: accounting.active_processes)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("r9_job_pid_list_header_only_buffer_rejected") do
      with_job do |job|
        child = job.spawn(self_exe, ["--child", "sleep", "900"])
        begin
          result = raw_job_process_ids(job, 0)
          {!result[:ok], details(error: result[:error], returned: result[:returned], assigned: result[:assigned], listed: result[:listed])}
        ensure
          close_child(child)
        end
      end
    end

    test("r9_job_pid_list_one_slot_two_children_reports_truncation") do
      job = ProcessSupervision.job
      a = b = nil.as(ProcessSupervision::Child?)
      begin
        a = job.spawn(self_exe, ["--child", "sleep", "1100"])
        b = job.spawn(self_exe, ["--child", "sleep", "1100"])
        result = raw_job_process_ids(job, 1)
        truncated = !result[:ok] || result[:assigned] > result[:listed]
        {truncated && result[:assigned] >= 2 && result[:listed] <= 1,
         details(ok: result[:ok], error: result[:error], returned: result[:returned], assigned: result[:assigned], listed: result[:listed], ids: result[:ids].join(","))}
      ensure
        close_child(a); close_child(b); close_job(job)
      end
    end

    test("r9_job_pid_list_descendant_membership") do
      marker = File.join(workdir, "r9-pid-list-tree-#{Process.pid}.txt")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "spawn-grandchild", marker])
        raise "grandchild marker not created" unless wait_for_file(marker)
        grandchild_pid = File.read(marker).strip.to_u64
        result = raw_job_process_ids(job, 8)
        expected = [child.pid.to_u64, grandchild_pid].sort
        {result[:ok] && (expected - result[:ids]).empty?,
         details(assigned: result[:assigned], listed: result[:listed], expected: expected.join(","), observed: result[:ids].sort.join(","))}
      ensure
        close_child(child); close_job(job)
      end
    end

    test("r9_job_pid_list_concurrent_exit_query_bounded") do
      job = ProcessSupervision.job
      children = [] of ProcessSupervision::Child
      begin
        16.times { |i| children << job.spawn(self_exe, ["--child", "sleep", (80 + i * 12).to_s]) }
        observations = [] of String
        deadline = Time.instant + 1.second
        while Time.instant < deadline
          result = raw_job_process_ids(job, 32)
          observations << "#{result[:ok]}:#{result[:assigned]}:#{result[:listed]}:#{result[:error]}"
          break if result[:ok] && result[:listed] == 0
          sleep 5.milliseconds
        end
        children.each { |child| child.wait(2.seconds) rescue nil }
        final = raw_job_process_ids(job, 32)
        {final[:ok] && final[:listed] == 0 && !observations.empty?,
         details(samples: observations.size, last_samples: observations.last(5).join("|"), final_assigned: final[:assigned], final_listed: final[:listed])}
      ensure
        children.each { |child| close_child(child) }; close_job(job)
      end
    end

    test("r9_second_completion_port_association_rejected") do
      job = ProcessSupervision.job
      first = second = LibC::HANDLE.null
      begin
        first = associate_raw_completion_port(job, 0x91_u64)
        second = LibC.CreateIoCompletionPort(INVALID_HANDLE_VALUE, LibC::HANDLE.null, Pointer(LibC::ULong).null, 1_u32)
        raise "CreateIoCompletionPort(second) failed" if second.null?
        associate = LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT.new(completionKey: Pointer(Void).new(0x92_u64), completionPort: second)
        rc = LibC.SetInformationJobObject(job.probe_native_handle, LibC::JOBOBJECTINFOCLASS::AssociateCompletionPortInformation,
          pointerof(associate).as(Void*), sizeof(LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT).to_u32)
        code = rc == 0 ? LibC.GetLastError : 0_u32
        {rc == 0, details(rc: rc, error: code, contract: "a Job may have only one associated completion port")}
      ensure
        LibC.CloseHandle(first) unless first.null?
        LibC.CloseHandle(second) unless second.null?
        close_job(job)
      end
    end

    test("r9_completion_port_key_roundtrip") do
      job = ProcessSupervision.job
      port = LibC::HANDLE.null
      child = nil.as(ProcessSupervision::Child?)
      begin
        key = 0x1234abcd_u64
        port = associate_raw_completion_port(job, key)
        child = job.spawn(self_exe, ["--child", "sleep", "180"])
        event = next_raw_completion(port, 1000_u32)
        {event[:ok] && event[:key] == key && event[:message] == JOB_OBJECT_MSG_NEW_PROCESS,
         details(ok: event[:ok], error: event[:error], message: event[:message], key_hex: event[:key].to_s(16), overlapped: event[:overlapped])}
      ensure
        close_child(child)
        LibC.CloseHandle(port) unless port.null?
        close_job(job)
      end
    end

    test("r9_notification_limit_write_threshold_roundtrip") do
      job = ProcessSupervision.job
      begin
        set = configure_write_notification(job, 64_u64 * 1024)
        info = WindowsProbeExtra::JobNotificationLimit.new
        returned = 0_u32
        rc = WindowsProbeExtra.QueryInformationJobObject(job.probe_native_handle, JOB_NOTIFICATION_LIMIT_CLASS,
          pointerof(info).as(Void*), sizeof(WindowsProbeExtra::JobNotificationLimit).to_u32, pointerof(returned))
        {set[:ok] && rc != 0 && (info.limit_flags & JOB_OBJECT_LIMIT_JOB_WRITE_BYTES) != 0 && info.io_write_bytes_limit == 64_u64 * 1024,
         details(set_ok: set[:ok], set_error: set[:error], query_rc: rc, returned: returned, flags_hex: info.limit_flags.to_s(16), write_limit: info.io_write_bytes_limit)}
      ensure
        close_job(job)
      end
    end

    test("r9_notification_limit_write_message_and_violation_query") do
      marker = File.join(workdir, "r9-notify-io-#{Process.pid}.json")
      path = File.join(workdir, "r9-notify-io-#{Process.pid}.bin")
      job = ProcessSupervision.job
      port = LibC::HANDLE.null
      child = nil.as(ProcessSupervision::Child?)
      begin
        port = associate_raw_completion_port(job, 0x55aa_u64)
        set = configure_write_notification(job, 64_u64 * 1024)
        raise "notification limit configuration failed: #{set[:error]}" unless set[:ok]
        child = job.spawn(self_exe, ["--child", "io-work", marker, path])
        messages = [] of UInt32
        # Notification limits are evaluated in the same ~7 s periodic pass as CPU-time limits; the message
        # arrived 0.6-4.7 s after the write in native runs, even when the child had already exited.
        deadline = Time.instant + 12.seconds
        while Time.instant < deadline && !messages.includes?(JOB_OBJECT_MSG_NOTIFICATION_LIMIT)
          event = next_raw_completion(port, 250_u32)
          messages << event[:message] if event[:ok]
        end
        child.wait(4.seconds)
        violation = query_limit_violation(job)
        flagged = (violation[:violation_flags] & JOB_OBJECT_LIMIT_JOB_WRITE_BYTES) != 0
        {messages.includes?(JOB_OBJECT_MSG_NOTIFICATION_LIMIT) && violation[:ok] && flagged && violation[:write_bytes] >= violation[:write_limit],
         details(messages: messages.join(","), violation_ok: violation[:ok], violation_error: violation[:error], limit_flags_hex: violation[:limit_flags].to_s(16), violation_flags_hex: violation[:violation_flags].to_s(16), write_bytes: violation[:write_bytes], write_limit: violation[:write_limit])}
      ensure
        close_child(child)
        LibC.CloseHandle(port) unless port.null?
        close_job(job)
        File.delete?(path); File.delete?(marker)
      end
    end

    test("r9_cross_job_concurrent_spawn_handle_isolation_2") do
      r9_cross_job_handle_isolation_case(2)
    end
    test("r9_cross_job_concurrent_spawn_handle_isolation_4") do
      r9_cross_job_handle_isolation_case(4)
    end
    test("r9_cross_job_concurrent_spawn_handle_isolation_8") do
      r9_cross_job_handle_isolation_case(8)
    end
    test("r9_cross_job_concurrent_spawn_handle_isolation_16") do
      r9_cross_job_handle_isolation_case(16)
    end
  end

  def self.run : Nil
    Dir.mkdir_p(workdir)
    note("environment", details(crystal: Crystal::VERSION, os: "windows", pid: Process.pid,
      executable: self_exe, workdir: workdir, pointer_bytes: sizeof(Void*)))
    token_note
    priority_checkpoint("start")

    test("win32_parent_job_membership") do
      in_job = LibC::BOOL.new(0)
      rc = WindowsProbeNative.IsProcessInJob(WindowsProbeNative.GetCurrentProcess, LibC::HANDLE.null, pointerof(in_job))
      {rc != 0, details(rc: rc, in_job: in_job, error: rc == 0 ? LibC.GetLastError : 0)}
    end

    test("self_stable_identity_and_scoped_handle") do
      h = ProcessHandle.current
      begin
        first = ProcessHandle.observe(Process.pid)
        second = ProcessHandle.lookup(Process.pid)
        windows = h.as(ProcessHandle::Windows)
        raw_pid = windows.with_native_handle(ProcessHandle::Windows::Access::QueryLimitedInformation) do |raw|
          WindowsProbeNative.GetProcessId(raw)
        end
        {h.alive? && first.state.live? && h.identity.same_process?(first.identity.not_nil!) &&
          second.try { |id| h.identity.same_process?(id) } == true && raw_pid == Process.pid,
         details(mechanism: h.mechanism, pid: h.pid, raw_pid: raw_pid,
           handle_generation: h.identity.generation, observation_generation: first.identity.try(&.generation),
           lookup_generation: second.try(&.generation))}
      ensure
        h.close
      end
    end

    test("invalid_pid_rejected") do
      outcome = "no_error"
      begin
        ProcessHandle.observe(0)
      rescue ArgumentError
        outcome = "argument_error"
      end
      {outcome == "argument_error", details(result: outcome)}
    end

    test("nonexistent_pid_observe") do
      pid = Int32::MAX
      result = ProcessHandle.observe(pid)
      {result.state.dead? || result.state.unknown?, details(pid: pid, state: result.state)}
    end

    test("single_child_wait_timeout_and_close") do
      child = Process.new(self_exe, ["--child", "sleep", "800"])
      h = nil.as(ProcessHandle?)
      reaped = false
      begin
        h = ProcessHandle.open(child.pid)
        expired = !h.wait(40.milliseconds)
        terminated = h.wait(3.seconds)
        status = child.wait
        reaped = true
        before_close = h.alive?
        h.close
        rejected = "no_error"
        begin
          h.wait(2.milliseconds)
        rescue ProcessHandle::Error::Closed
          rejected = "closed"
        end
        {expired && terminated && !before_close && status.success? && h.closed? && rejected == "closed",
         details(pid: child.pid, short_wait_timed_out: expired, long_wait_terminated: terminated,
           alive_after_exit: before_close, wait_after_close: rejected, exit_code: status.exit_code)}
      ensure
        h.try &.close
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("repeated_short_registered_waits") do
      child = Process.new(self_exe, ["--child", "sleep", "1100"])
      h = nil.as(ProcessHandle?)
      reaped = false
      begin
        h = ProcessHandle.open(child.pid)
        count = 0
        8.times do
          count += 1 unless h.wait(15.milliseconds)
        end
        ended = h.wait(3.seconds)
        status = child.wait
        reaped = true
        {count >= 6 && ended && status.success?, details(timeout_count: count, wait_count: 8, final_wait: ended)}
      ensure
        h.try &.close
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("parallel_fiber_wait_fanout") do
      child = Process.new(self_exe, ["--child", "sleep", "650"])
      h = nil.as(ProcessHandle?)
      reaped = false
      begin
        h = ProcessHandle.open(child.pid)
        responses = Channel(String).new(8)
        8.times do
          spawn do
            responses.send(wait_result(h.not_nil!, 3.seconds))
          end
        end
        answers = Array(String).new(8) { responses.receive }
        status = child.wait
        reaped = true
        {answers.all? { |x| x == "true" } && status.success?,
         details(answers: answers.join(","), exit_code: status.exit_code,
           caveat: "fiber fanout is not native-parallel proof")}
      ensure
        h.try &.close
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("raw_thread_wait_bridge_and_owner_close") do
      child = Process.new(self_exe, ["--child", "sleep", "900"])
      h = nil.as(ProcessHandle?)
      reaped = false
      begin
        h = ProcessHandle.open(child.pid)
        outcome = "not_started"
        waiting = Atomic(Bool).new(false)
        wait_handle = h
        worker = Thread.new do
          waiting.set(true)
          outcome = wait_result(wait_handle, 3.seconds)
        end
        deadline = Time.instant + 1.second
        until waiting.get || Time.instant >= deadline
          sleep 1.millisecond
        end
        sleep 40.milliseconds
        h.close
        worker.join
        status = child.wait
        reaped = true
        # Both results are legal: the wait may acquire a duplicated HANDLE
        # before close, or may be rejected if close wins effect admission.
        accepted = outcome == "true" || outcome.starts_with?("ProcessHandle::Error::Closed:")
        {accepted && status.success?,
         details(result: outcome, child_exit: status.exit_code,
           note: "accepts pre-close admission or post-close Closed, not false termination")}
      ensure
        h.try &.close
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("empty_job_close_idempotent") do
      job = ProcessSupervision.job
      begin
        empty = job.empty?
        job.close
        job.close
        {empty && job.closed? && job.kill_on_close? && !job.soft_termination?,
         details(empty: empty, closed: job.closed?, kill_on_close: job.kill_on_close?, soft: job.soft_termination?)}
      ensure
        close_job(job)
      end
    end

    test("supervised_spawn_argv_env_and_cwd") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 4_u32))
      child = nil.as(ProcessSupervision::Child?)
      marker = File.join(workdir, "win-argv-#{Process.pid}.json")
      args = ["", "alpha beta", "quoted\"value", "trailing\\\\", "snowman-☃"]
      begin
        child = job.spawn(self_exe, ["--child", "args", marker] + args,
          env: {"PROCESS_PROBE_TOKEN" => "win-probe-0005"}, chdir: workdir)
        status = child.wait(3.seconds)
        raise "supervised child timed out" unless status
        payload = JSON.parse(File.read(marker))
        actual = payload["args"].as_a.map(&.as_s)
        events = job.limit_events
        accounting = job.accounting
        {status.success? && actual == args && payload["probe_env"].as_s == "win-probe-0005" &&
          Path[payload["cwd"].as_s].expand.to_s.downcase == Path[workdir].expand.to_s.downcase,
         details(exit_code: status.exit_code, args_exact: actual == args,
           env_exact: payload["probe_env"].as_s == "win-probe-0005",
           cwd: payload["cwd"].as_s, job_total: accounting.total_processes,
           job_active: accounting.active_processes, event_count: events.size)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("handle_allowlist_blocks_unrelated_inheritable_event") do
      security = LibC::SECURITY_ATTRIBUTES.new(
        nLength: sizeof(LibC::SECURITY_ATTRIBUTES).to_u32,
        lpSecurityDescriptor: Pointer(Void).null,
        bInheritHandle: 1
      )
      event = WindowsProbeNative.CreateEventW(pointerof(security), 1, 0, Pointer(UInt16).null)
      raise "CreateEventW failed: #{LibC.GetLastError}" if event.null?
      job = nil.as(ProcessSupervision::Windows::Job?)
      child = nil.as(ProcessSupervision::Child?)
      marker = File.join(workdir, "win-unrelated-handle-#{Process.pid}.json")
      begin
        job = ProcessSupervision.job
        child = job.spawn(self_exe, ["--child", "check-handle", marker, event.address.to_s])
        status = child.wait(3.seconds)
        raise "child did not complete" unless status
        payload = JSON.parse(File.read(marker))
        accessible = payload["accessible"].as_bool
        {status.success? && !accessible,
         details(handle: event.address.to_s, wrongly_inherited: accessible,
           child_error_code: payload["error"].as_i, child_exit_code: status.exit_code)}
      ensure
        close_child(child)
        close_job(job)
        LibC.CloseHandle(event)
      end
    end

    test("job_close_kills_direct_child_and_descendant") do
      marker = File.join(workdir, "win-grandchild-#{Process.pid}.txt")
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      grandchild = nil.as(ProcessHandle?)
      begin
        child = job.spawn(self_exe, ["--child", "spawn-grandchild", marker])
        raise "grandchild marker was not created" unless wait_for_file(marker)
        grandchild_pid = File.read(marker).strip.to_i64
        grandchild = ProcessHandle.open(grandchild_pid)
        parent_pid = child.pid
        before = child.handle.alive? && grandchild.alive?
        job.close
        parent_terminated = child.handle.wait(3.seconds)
        grandchild_terminated = grandchild.wait(3.seconds)
        child_status = child.wait(3.seconds)
        {before && parent_terminated && grandchild_terminated && !child_status.nil?,
         details(parent_pid: parent_pid, grandchild_pid: grandchild_pid, before_alive: before,
           parent_terminated: parent_terminated, grandchild_terminated: grandchild_terminated,
           direct_exit_code: child_status.try(&.exit_code?),
           direct_exit_reason: child_status.try(&.exit_reason),
           note: "Windows Job kill-on-close exit code is observational, not proof of graceful exit")}
      ensure
        grandchild.try &.close
        close_child(child)
        close_job(job)
      end
    end

    test("job_owner_abrupt_death_kills_child") do
      # The Job owner is intentionally *not* the test process. A separate
      # controller creates an unnamed kill-on-close Job and then gets
      # terminated, simulating a controller crash without touching any
      # unrelated process. The descendant must die on kernel owner cleanup.
      marker = File.join(workdir, "win-owner-death-#{Process.pid}.txt")
      File.delete(marker) if File.exists?(marker)
      controller = Process.new(self_exe, ["--child", "job-controller", marker])
      descendant = nil.as(ProcessHandle?)
      reaped = false
      begin
        raise "job owner did not publish child PID" unless wait_for_file(marker)
        child_pid = File.read(marker).strip.to_i64
        descendant = ProcessHandle.open(child_pid)
        before = descendant.alive?
        controller.terminate
        owner_status = controller.wait
        reaped = true
        terminated = descendant.wait(3.seconds)
        {before && terminated,
         details(child_pid: child_pid, owner_pid: controller.pid,
           before_alive: before, descendant_terminated: terminated,
           owner_exit_reason: owner_status.exit_reason,
           note: "last Job HANDLE closed by OS on abrupt controller termination")}
      ensure
        if h = descendant
          begin
            h.kill if !h.closed? && h.alive?
          rescue
          end
          begin
            h.close
          rescue
          end
        end
        cleanup(controller, reaped)
      end
    end

    test("job_shutdown_hard_tier") do
      job = ProcessSupervision.job
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "4500"])
        report = job.shutdown(grace: 100.milliseconds, kill_after: 3.seconds, close: true)
        terminated = child.handle.wait(2.seconds)
        {report.kill_requested? && !report.terminate_requested? && report.drained? && report.closed? && terminated,
         details(kill_requested: report.kill_requested?, terminate_requested: report.terminate_requested?,
           drained: report.drained?, closed: report.closed?, child_terminated: terminated)}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_adopt_existing_child_then_close") do
      child = Process.new(self_exe, ["--child", "sleep", "4200"])
      h = nil.as(ProcessHandle?)
      job = nil.as(ProcessSupervision::Windows::Job?)
      reaped = false
      begin
        h = ProcessHandle.open(child.pid)
        job = ProcessSupervision.job
        job.adopt(h)
        in_any_job = LibC::BOOL.new(0)
        rc = h.as(ProcessHandle::Windows).with_native_handle(ProcessHandle::Windows::Access::QueryLimitedInformation) do |raw|
          WindowsProbeNative.IsProcessInJob(raw, LibC::HANDLE.null, pointerof(in_any_job))
        end
        job.close
        terminated = h.wait(3.seconds)
        status = child.wait
        reaped = true
        {rc != 0 && in_any_job != 0 && terminated,
         details(pid: child.pid, in_job: in_any_job, membership_query_rc: rc, terminated: terminated,
           exit_code: status.exit_code)}
      ensure
        close_job(job)
        h.try &.close
        child.try { |c| cleanup(c, reaped || false) }
      end
    end

    test("job_active_process_limit_isolation") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 1_u32))
      first = nil.as(ProcessSupervision::Child?)
      second = nil.as(ProcessSupervision::Child?)
      begin
        first = job.spawn(self_exe, ["--child", "sleep", "4400"])
        second_result = "unexpected_success"
        begin
          second = job.spawn(self_exe, ["--child", "sleep", "1500"])
        rescue ex
          second_result = "#{ex.class.name}:#{ex.message}"
        end
        alive_first = first.handle.alive?
        accounting = job.accounting
        events = job.limit_events
        {second.nil? && alive_first && accounting.active_processes >= 1,
         details(second_spawn: second_result, first_alive: alive_first, active: accounting.active_processes,
           total: accounting.total_processes, limit_events: events.map(&.kind).join(","))}
      ensure
        close_child(second)
        close_child(first)
        close_job(job)
      end
    end

    test("limit_event_reader_concurrent_close") do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(active_processes: 3_u32))
      child = nil.as(ProcessSupervision::Child?)
      begin
        child = job.spawn(self_exe, ["--child", "sleep", "900"])
        ready = Atomic(Bool).new(false)
        go = Atomic(Bool).new(false)
        done = Atomic(Bool).new(false)
        reader_result = Atomic(Int32).new(0) # 0 clean, 1 Closed, 2 unexpected
        Thread.new do
          ready.set(true)
          until go.get
            Thread.yield
          end
          begin
            700.times { job.limit_events }
          rescue ProcessSupervision::Error::Closed
            reader_result.set(1)
          rescue
            reader_result.set(2)
          ensure
            done.set(true)
          end
        end
        wait_until(1.second) { ready.get }
        go.set(true)
        job.close
        settled = wait_until(2.seconds) { done.get }
        terminated = child.handle.wait(2.seconds)
        result = reader_result.get
        {settled && result != 2 && job.closed? && terminated,
         details(reader: result == 0 ? "completed_before_close" : result == 1 ? "closed_after_close_won" : "unexpected_error",
           job_closed: job.closed?, child_terminated: terminated, settled: settled,
           contract: "operations admitted before close may finish; later operations fail Closed")}
      ensure
        close_child(child)
        close_job(job)
      end
    end

    test("job_validation_failure_does_not_leak") do
      job = ProcessSupervision.job
      begin
        outcome = "not_rejected"
        begin
          job.spawn("nope.cmd")
        rescue ProcessSupervision::Error::Unsupported
          outcome = "unsupported"
        end
        {outcome == "unsupported" && job.empty?, details(batch_file: outcome, empty: job.empty?)}
      ensure
        close_job(job)
      end
    end

    test("r7_finite_wait_sequence_1ms_x16") do
      r7_repeated_wait_timeout_case(1.millisecond, 16, 620)
    end

    test("r7_finite_wait_sequence_5ms_x16") do
      r7_repeated_wait_timeout_case(5.milliseconds, 16, 620)
    end

    test("r7_finite_wait_sequence_15ms_x16") do
      r7_repeated_wait_timeout_case(15.milliseconds, 16, 720)
    end

    test("r7_finite_wait_sequence_30ms_x8") do
      r7_repeated_wait_timeout_case(30.milliseconds, 8, 720)
    end

    test("r7_parent_immediate_job_limit_snapshot") do
      info = query_current_job_extended
      {parent_in_job? ? !info.nil? : info.nil?,
       details(parent_in_job: parent_in_job?, flags_hex: info.try(&.basicLimitInformation.limitFlags.to_s(16)),
         process_time_100ns: info.try(&.basicLimitInformation.perProcessUserTimeLimit),
         job_time_100ns: info.try(&.basicLimitInformation.perJobUserTimeLimit))}
    end

    run_expanded
    priority_checkpoint("after_expanded")
    run_exhaustive
    priority_checkpoint("after_exhaustive")
    run_deep_native_matrix
    priority_checkpoint("after_deep_native")
    run_completion_matrix
    priority_checkpoint("after_completion")
    run_r6_matrix
    run_r9_source_matrix
    run_r10_hardening_matrix
  ensure
    finish
  end
end

if ARGV[0]? == "--child"
  NativeProbe.child_mode
else
  NativeProbe.run
end
