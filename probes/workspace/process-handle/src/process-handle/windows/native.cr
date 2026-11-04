{% if flag?(:win32) %}
  @[Link("kernel32")]
  private lib LibProcessHandleWin32
    alias WaitOrTimerCallback = (Void*, LibC::BOOLEAN) ->

    fun GetCurrentProcess : LibC::HANDLE
    fun DuplicateHandle(source_process : LibC::HANDLE, source_handle : LibC::HANDLE,
                        target_process : LibC::HANDLE, target_handle : LibC::HANDLE*,
                        desired_access : UInt32, inherit_handle : LibC::BOOL,
                        options : UInt32) : LibC::BOOL
    fun RegisterWaitForSingleObject(new_wait_object : LibC::HANDLE*, object : LibC::HANDLE,
                                    callback : WaitOrTimerCallback, context : Void*,
                                    milliseconds : UInt32, flags : UInt32) : LibC::BOOL
    fun UnregisterWaitEx(wait_handle : LibC::HANDLE, completion_event : LibC::HANDLE) : LibC::BOOL
  end

  private module ProcessHandle::Windows::Native
    PROCESS_TERMINATE                 =      0x0001_u32
    PROCESS_SET_QUOTA                 =      0x0100_u32
    PROCESS_QUERY_LIMITED_INFORMATION =      0x1000_u32
    SYNCHRONIZE                       =    0x100000_u32
    DUPLICATE_SAME_ACCESS             =           2_u32
    WAIT_OBJECT_0                     =           0_u32
    WAIT_TIMEOUT                      =         258_u32
    WAIT_FAILED                       = 0xffff_ffff_u32
    INFINITE                          = 0xffff_ffff_u32
    INVALID_HANDLE_VALUE              = LibC::HANDLE.new(UInt64::MAX)
    WT_EXECUTEINWAITTHREAD            = 4_u32
    WT_EXECUTEONLYONCE                = 8_u32
    REGISTERED_WAIT_FLAGS             = WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE
    ERROR_ACCESS_DENIED               =  5_u32
    ERROR_INVALID_PARAMETER           = 87_u32

    def self.error(operation : String, code : UInt32 = LibC.GetLastError) : ProcessHandle::Error::Native
      native = WinError.new(code)
      ProcessHandle::Error::Native.new(operation, native.message, code.to_i64)
    end

    def self.open_process(pid : Int64, access : UInt32, operation : String = "OpenProcess") : LibC::HANDLE
      raise ArgumentError.new("pid must be positive") unless pid > 0
      raise ArgumentError.new("pid exceeds native DWORD range") if pid > UInt32::MAX
      handle = LibC.OpenProcess(access, 0, pid.to_u32)
      return handle unless handle.null?
      code = LibC.GetLastError
      case code
      when ERROR_INVALID_PARAMETER
        raise ProcessHandle::Error::NoSuchProcess.new(pid)
      when ERROR_ACCESS_DENIED
        raise ProcessHandle::Error::AccessDenied.new(pid, WinError.new(code).message)
      else
        raise error(operation, code)
      end
    end

    def self.open_observer(pid : Int64) : LibC::HANDLE
      open_process(pid, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)
    end

    def self.open_terminator(pid : Int64) : LibC::HANDLE
      open_process(pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, "OpenProcess(PROCESS_TERMINATE)")
    end

    def self.creation_time(handle : LibC::HANDLE, operation : String = "GetProcessTimes") : UInt64
      creation_time = uninitialized LibC::FILETIME
      exit_time = uninitialized LibC::FILETIME
      kernel_time = uninitialized LibC::FILETIME
      user_time = uninitialized LibC::FILETIME
      if LibC.GetProcessTimes(handle, pointerof(creation_time), pointerof(exit_time), pointerof(kernel_time), pointerof(user_time)) == 0
        raise error(operation)
      end
      (creation_time.dwHighDateTime.to_u64 << 32) | creation_time.dwLowDateTime.to_u64
    end

    def self.close_handle(handle : LibC::HANDLE, operation : String = "CloseHandle") : Nil
      return if handle.null?
      raise error(operation) if LibC.CloseHandle(handle) == 0
    end

    def self.close_native_handle(handle : LibC::HANDLE) : Nil
      LibC.CloseHandle(handle) unless handle.null?
    end

    # Checked cleanup when it is the only possible failure; no-throw cleanup
    # when an operation already owns the primary error. This is the same
    # distinction PTY uses between owner-controlled handles and rollback /
    # temporary-observation handles.
    def self.close_preserving_primary(handle : LibC::HANDLE, operation : String, primary : Exception?) : Nil
      if primary
        close_native_handle(handle)
      else
        close_handle(handle, operation)
      end
    end

    def self.duplicate(handle : LibC::HANDLE, operation : String = "DuplicateHandle") : LibC::HANDLE
      raise ProcessHandle::Error::Closed.new("process handle is closed") if handle.null?
      current = LibProcessHandleWin32.GetCurrentProcess
      duplicate = LibC::HANDLE.null
      ok = LibProcessHandleWin32.DuplicateHandle(
        current, handle, current, pointerof(duplicate), 0_u32, 0, DUPLICATE_SAME_ACCESS
      )
      raise error(operation) if ok == 0
      duplicate
    end

    def self.register_wait(handle : LibC::HANDLE, callback : LibProcessHandleWin32::WaitOrTimerCallback, context : Void*,
                           milliseconds : UInt32) : LibC::HANDLE
      wait_handle = LibC::HANDLE.null
      ok = LibProcessHandleWin32.RegisterWaitForSingleObject(
        pointerof(wait_handle), handle, callback, context, milliseconds, REGISTERED_WAIT_FLAGS
      )
      raise error("RegisterWaitForSingleObject") if ok == 0
      wait_handle
    end

    def self.registered_wait_milliseconds(timeout : Time::Span) : UInt32
      return 0_u32 if timeout <= Time::Span.zero

      max_milliseconds = (INFINITE - 1_u32).to_u64
      seconds = timeout.to_i.to_u64
      return (INFINITE - 1_u32) if seconds > max_milliseconds // 1000_u64

      milliseconds = seconds * 1000_u64
      if nanos = timeout.nanoseconds
        milliseconds += (nanos.to_u64 + 999_999_u64) // 1_000_000_u64 if nanos > 0
      end
      {milliseconds, max_milliseconds}.min.to_u32
    end

    def self.unregister_wait_blocking(wait_handle : LibC::HANDLE) : Nil
      return if wait_handle.null?
      if LibProcessHandleWin32.UnregisterWaitEx(wait_handle, INVALID_HANDLE_VALUE) == 0
        raise error("UnregisterWaitEx")
      end
    end

    def self.raw_write_one_byte(handle : LibC::HANDLE) : {Bool, UInt32, UInt32}
      byte = 1_u8
      written = 0_u32
      if LibC.WriteFile(handle, pointerof(byte).as(Void*), 1_u32, pointerof(written), Pointer(LibC::OVERLAPPED).null) == 0
        {false, written, LibC.GetLastError}
      else
        {true, written, 0_u32}
      end
    end
  end
{% end %}
