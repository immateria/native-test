{% if flag?(:win32) %}
  class ProcessHandle::Windows
    def self.observe(pid : Int64) : ProcessHandle::Observation
      handle = Native.open_observer(pid)
      primary = nil.as(Exception?)
      begin
        identity = ProcessHandle::Identity.new(pid, Native.creation_time(handle, "GetProcessTimes(process observation)"))
        state = case rc = LibC.WaitForSingleObject(handle, 0_u32)
                when Native::WAIT_TIMEOUT
                  ProcessHandle::Observation::State::Live
                when Native::WAIT_OBJECT_0
                  ProcessHandle::Observation::State::Dead
                when Native::WAIT_FAILED
                  raise Native.error("WaitForSingleObject(process observation)")
                else
                  raise ProcessHandle::Error::Native.new(
                    "WaitForSingleObject(process observation)",
                    "unexpected wait result #{rc}",
                    rc.to_i64
                  )
                end
        ProcessHandle::Observation.new(pid, state, identity)
      rescue ex
        primary = ex
        raise ex
      ensure
        Native.close_preserving_primary(handle, "CloseHandle(process observation)", primary)
      end
    rescue ProcessHandle::Error::NoSuchProcess
      ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Dead, nil)
    rescue ProcessHandle::Error::AccessDenied
      ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Unknown, nil)
    end

    def self.lookup_identity(pid : Int64) : ProcessHandle::Identity?
      handle = Native.open_observer(pid)
      primary = nil.as(Exception?)
      begin
        ProcessHandle::Identity.new(pid, Native.creation_time(handle))
      rescue ex
        primary = ex
        raise ex
      ensure
        Native.close_preserving_primary(handle, "CloseHandle(process lookup)", primary)
      end
    rescue ProcessHandle::Error::NoSuchProcess
      nil
    end

    @native : LibC::HANDLE
    @mutex = Thread::Mutex.new

    def self.open(pid : Int64) : self
      raise ArgumentError.new("pid must be positive") unless pid > 0
      native = Native.open_observer(pid)
      begin
        identity = ProcessHandle::Identity.new(pid, Native.creation_time(native))
        new(identity, native)
      rescue ex
        Native.close_native_handle(native)
        raise ex
      end
    end

    private def initialize(identity : ProcessHandle::Identity, @native : LibC::HANDLE)
      super(identity)
    end

    def mechanism : ProcessHandle::Mechanism
      ProcessHandle::Mechanism::Win32Handle
    end

    def alive? : Bool
      @mutex.synchronize do
        handle = checked_handle
        case rc = LibC.WaitForSingleObject(handle, 0_u32)
        when Native::WAIT_OBJECT_0
          false
        when Native::WAIT_TIMEOUT
          true
        when Native::WAIT_FAILED
          raise Native.error("WaitForSingleObject")
        else
          raise ProcessHandle::Error::Native.new("WaitForSingleObject", "unexpected wait result #{rc}", rc.to_i64)
        end
      end
    end

    def wait(timeout : Time::Span? = nil) : Bool
      run_on_execution_context("process-handle-windows-wait") do
        wait_on_execution_context(timeout)
      end
    end

    private def wait_on_execution_context(timeout : Time::Span?) : Bool
      validate_timeout(timeout)
      duplicate = @mutex.synchronize { Native.duplicate(checked_handle) }
      begin
        FiberWait.wait(duplicate, timeout)
      ensure
        # A duplicate exists only to observe readiness. PTY intentionally uses
        # no-throw cleanup here so a post-observation CloseHandle anomaly does
        # not replace the wait result or wait failure.
        Native.close_native_handle(duplicate)
      end
    end

    def terminate : Nil
      raise ProcessHandle::Error::Unsupported.new(
        "Windows has no general cooperative termination operation for an arbitrary process HANDLE"
      )
    end

    def kill : Nil
      handle = LibC::HANDLE.null

      @mutex.synchronize do
        owner = checked_handle
        case rc = LibC.WaitForSingleObject(owner, 0_u32)
        when Native::WAIT_OBJECT_0
          return
        when Native::WAIT_TIMEOUT
        when Native::WAIT_FAILED
          raise Native.error("WaitForSingleObject(process termination admission)")
        else
          raise ProcessHandle::Error::Native.new(
            "WaitForSingleObject(process termination admission)",
            "unexpected wait result #{rc}",
            rc.to_i64
          )
        end

        handle = Native.open_terminator(pid)
        begin
          generation = Native.creation_time(handle, "GetProcessTimes(process termination)")
          unless generation == identity.generation
            raise ProcessHandle::Error::NoSuchProcess.new(pid)
          end
        rescue ex
          Native.close_preserving_primary(handle, "CloseHandle(process termination)", ex)
          handle = LibC::HANDLE.null
          raise ex
        end
      end

      primary = nil.as(Exception?)
      begin
        if LibC.TerminateProcess(handle, 137_u32) == 0
          raise Native.error("TerminateProcess")
        end
      rescue ex
        primary = ex
        raise ex
      ensure
        Native.close_preserving_primary(handle, "CloseHandle(process termination)", primary)
      end
    rescue ProcessHandle::Error::NoSuchProcess
      nil
    end

    # Yields a fresh process HANDLE with the requested Windows rights after
    # verifying that the PID still names this exact creation-time identity.
    # The native handle is always closed when the block exits.
    def with_native_handle(access : Access, & : LibC::HANDLE -> T) : T forall T
      requested = access.value | Access::QueryLimitedInformation.value
      native = LibC::HANDLE.null

      @mutex.synchronize do
        checked_handle
        native = Native.open_process(pid, requested, "OpenProcess(scoped native handle)")
        begin
          generation = Native.creation_time(native, "GetProcessTimes(scoped native handle)")
          unless generation == identity.generation
            raise ProcessHandle::Error::NoSuchProcess.new(pid)
          end
        rescue ex
          Native.close_preserving_primary(native, "CloseHandle(scoped native handle)", ex)
          native = LibC::HANDLE.null
          raise ex
        end
      end

      primary = nil.as(Exception?)
      begin
        yield native
      rescue ex
        primary = ex
        raise ex
      ensure
        Native.close_preserving_primary(native, "CloseHandle(scoped native handle)", primary)
      end
    end

    def close : Nil
      @mutex.synchronize do
        return if @native.null?
        Native.close_handle(@native, "CloseHandle(process)")
        @native = LibC::HANDLE.null
      end
    end

    def closed? : Bool
      @mutex.synchronize { @native.null? }
    end

    private def checked_handle : LibC::HANDLE
      raise ProcessHandle::Error::Closed.new("process handle is closed") if @native.null?
      @native
    end
  end
{% end %}

{% if flag?(:win32) %}
  require "c/tlhelp32"

  @[Link("kernel32")]
  private lib LibProcessHandleWinControl
    struct ProcessMemoryCounters
      cb : UInt32
      page_fault_count : UInt32
      peak_working_set_size : LibC::SizeT
      working_set_size : LibC::SizeT
      quota_peak_paged_pool_usage : LibC::SizeT
      quota_paged_pool_usage : LibC::SizeT
      quota_peak_non_paged_pool_usage : LibC::SizeT
      quota_non_paged_pool_usage : LibC::SizeT
      pagefile_usage : LibC::SizeT
      peak_pagefile_usage : LibC::SizeT
    end

    struct IoCounters
      read_operations : UInt64
      write_operations : UInt64
      other_operations : UInt64
      read_bytes : UInt64
      write_bytes : UInt64
      other_bytes : UInt64
    end

    fun K32GetProcessMemoryInfo(process : LibC::HANDLE, counters : ProcessMemoryCounters*, size : UInt32) : LibC::BOOL
    fun GetProcessIoCounters(process : LibC::HANDLE, counters : IoCounters*) : LibC::BOOL
    fun GetProcessTimes(process : LibC::HANDLE, creation : LibC::FILETIME*, exit : LibC::FILETIME*,
                        kernel : LibC::FILETIME*, user : LibC::FILETIME*) : LibC::BOOL
  end

  @[Link("ntdll")]
  private lib LibProcessHandleNtdll
    fun NtSuspendProcess(process : LibC::HANDLE) : Int32
    fun NtResumeProcess(process : LibC::HANDLE) : Int32
  end

  class ProcessHandle::Windows
    # Windows delivers no POSIX signals: use `kill`, `suspend` and `resume` (and, for a console child in its own process
    # group, `ProcessSupervision`'s `request_stop`).
    def signal(signal : Signal) : Nil
      raise ProcessHandle::Error::Unsupported.new("Windows processes cannot be sent #{signal}")
    end

    # Suspends every thread of the process (NtSuspendProcess; nests: resume once per suspend).
    def suspend : Nil
      with_native_handle(Access::SuspendResume) do |native|
        status = LibProcessHandleNtdll.NtSuspendProcess(native)
        raise ProcessHandle::Error::Native.new("NtSuspendProcess", "NTSTATUS 0x#{status.to_u32.to_s(16)}", status.to_i64) unless status == 0
      end
    end

    def resume : Nil
      with_native_handle(Access::SuspendResume) do |native|
        status = LibProcessHandleNtdll.NtResumeProcess(native)
        raise ProcessHandle::Error::Native.new("NtResumeProcess", "NTSTATUS 0x#{status.to_u32.to_s(16)}", status.to_i64) unless status == 0
      end
    end

    def usage : ProcessHandle::Usage
      with_native_handle(Access::VmRead) do |native|
        creation = exit = kernel = user = LibC::FILETIME.new
        if LibProcessHandleWinControl.GetProcessTimes(native, pointerof(creation), pointerof(exit), pointerof(kernel), pointerof(user)) == 0
          raise ProcessHandle::Error::Native.new("GetProcessTimes", "failed", LibC.GetLastError.to_i64)
        end
        memory = LibProcessHandleWinControl::ProcessMemoryCounters.new
        memory.cb = sizeof(LibProcessHandleWinControl::ProcessMemoryCounters).to_u32
        have_memory = LibProcessHandleWinControl.K32GetProcessMemoryInfo(native, pointerof(memory), memory.cb) != 0
        io = LibProcessHandleWinControl::IoCounters.new
        have_io = LibProcessHandleWinControl.GetProcessIoCounters(native, pointerof(io)) != 0
        span = ->(time : LibC::FILETIME) { (((time.dwHighDateTime.to_u64 << 32) | time.dwLowDateTime.to_u64) * 100).to_i64.nanoseconds }
        ProcessHandle::Usage.new(
          user_time: span.call(user), system_time: span.call(kernel),
          resident_bytes: have_memory ? memory.working_set_size.to_u64 : nil,
          peak_resident_bytes: have_memory ? memory.peak_working_set_size.to_u64 : nil,
          read_bytes: have_io ? io.read_bytes : nil, written_bytes: have_io ? io.write_bytes : nil)
      end
    end

    def self.snapshot : Array(ProcessHandle::Entry)
      snapshot = LibC.CreateToolhelp32Snapshot(LibC::TH32CS_SNAPPROCESS, 0_u32)
      raise ProcessHandle::Error::Native.new("CreateToolhelp32Snapshot", "failed", LibC.GetLastError.to_i64) if snapshot.address == UInt64::MAX
      entries = [] of ProcessHandle::Entry
      begin
        entry = LibC::PROCESSENTRY32W.new
        entry.dwSize = sizeof(LibC::PROCESSENTRY32W).to_u32
        ok = LibC.Process32FirstW(snapshot, pointerof(entry))
        while ok != 0
          length = entry.szExeFile.index(0_u16) || entry.szExeFile.size
          name = String.from_utf16(Slice.new(entry.szExeFile.to_unsafe, length))
          entries << ProcessHandle::Entry.new(entry.th32ProcessID.to_i64, entry.th32ParentProcessID.to_i64, name)
          ok = LibC.Process32NextW(snapshot, pointerof(entry))
        end
      ensure
        LibC.CloseHandle(snapshot)
      end
      entries
    end
  end
{% end %}
