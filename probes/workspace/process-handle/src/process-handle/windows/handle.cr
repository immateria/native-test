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
