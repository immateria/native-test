{% if flag?(:win32) %}
  module ProcessSupervision::Windows
    # Runs this program as a Windows service, and installs, starts, stops and queries services.
    #
    # ```
    # ProcessSupervision::Windows::Service.run("my-supervisor") do |service|
    #   job = ProcessSupervision.job
    #   worker = job.spawn("C:\\app\\worker.exe")
    #   service.wait_for_stop          # STOP or system shutdown
    #   job.shutdown(grace: 5.seconds) # the Job ends every worker, also if this process is killed
    # end
    # ```
    #
    # How it is wired (measured in explore/windows/crystal_service.cr, Server 2022 and 2025): the SCM calls
    # `ServiceMain` on a thread it creates and the control handler on the thread that called
    # `StartServiceCtrlDispatcherW`. The dispatcher runs in an isolated execution context; `ServiceMain` and the handler
    # only make Win32 calls (no Crystal allocation: the SCM's thread is unknown to the garbage collector) and wake the
    # program's fibers by writing one byte to a pipe. The block runs on the calling fiber.
    #
    # A service has no standard streams: Crystal turns them into closed streams, so `STDOUT.puts` raises
    # `IO::Error` (log to a file). Start one child Job inside the block: its kill-on-close ends the workers when the
    # service process is killed (measured: `taskkill /F` of the service took the worker with it).
    class Service
      @[Link("advapi32")]
      lib LibService
        alias ServiceMainProc = UInt32, UInt16** -> Void
        alias HandlerProc = UInt32, UInt32, Void*, Void* -> UInt32

        struct SERVICE_TABLE_ENTRYW
          name : UInt16*
          proc : ServiceMainProc
        end

        struct SERVICE_STATUS
          service_type : UInt32
          current_state : UInt32
          controls_accepted : UInt32
          win32_exit_code : UInt32
          specific_exit_code : UInt32
          check_point : UInt32
          wait_hint : UInt32
        end

        struct SERVICE_STATUS_PROCESS
          service_type : UInt32
          current_state : UInt32
          controls_accepted : UInt32
          win32_exit_code : UInt32
          specific_exit_code : UInt32
          check_point : UInt32
          wait_hint : UInt32
          process_id : UInt32
          service_flags : UInt32
        end

        struct SC_ACTION
          type : UInt32
          delay : UInt32
        end

        struct SERVICE_FAILURE_ACTIONSW
          reset_period : UInt32
          reboot_msg : UInt16*
          command : UInt16*
          actions_count : UInt32
          actions : SC_ACTION*
        end

        struct SERVICE_DESCRIPTIONW
          description : UInt16*
        end

        fun StartServiceCtrlDispatcherW(table : SERVICE_TABLE_ENTRYW*) : Int32
        fun RegisterServiceCtrlHandlerExW(name : UInt16*, handler : HandlerProc, context : Void*) : Void*
        fun SetServiceStatus(handle : Void*, status : SERVICE_STATUS*) : Int32
        fun OpenSCManagerW(machine : UInt16*, database : UInt16*, access : UInt32) : Void*
        fun CreateServiceW(manager : Void*, name : UInt16*, display_name : UInt16*, access : UInt32, type : UInt32,
                           start_type : UInt32, error_control : UInt32, binary_path : UInt16*, load_order_group : UInt16*,
                           tag_id : UInt32*, dependencies : UInt16*, account : UInt16*, password : UInt16*) : Void*
        fun OpenServiceW(manager : Void*, name : UInt16*, access : UInt32) : Void*
        fun StartServiceW(service : Void*, argc : UInt32, argv : UInt16**) : Int32
        fun ControlService(service : Void*, control : UInt32, status : SERVICE_STATUS*) : Int32
        fun QueryServiceStatusEx(service : Void*, level : UInt32, buffer : UInt8*, size : UInt32, needed : UInt32*) : Int32
        fun DeleteService(service : Void*) : Int32
        fun CloseServiceHandle(handle : Void*) : Int32
        fun ChangeServiceConfig2W(service : Void*, level : UInt32, info : Void*) : Int32
      end

      enum State : UInt32
        Stopped         = 1
        StartPending    = 2
        StopPending     = 3
        Running         = 4
        ContinuePending = 5
        PausePending    = 6
        Paused          = 7
      end

      enum StartType : UInt32
        Automatic = 2
        Demand    = 3
        Disabled  = 4
      end

      private SERVICE_WIN32_OWN_PROCESS       =    0x10_u32
      private SERVICE_ACCEPT_STOP             =     0x1_u32
      private SERVICE_ACCEPT_SHUTDOWN         =     0x4_u32
      private SERVICE_CONTROL_STOP            =       1_u32
      private SERVICE_CONTROL_INTERROGATE     =       4_u32
      private SERVICE_CONTROL_SHUTDOWN        =       5_u32
      private ERROR_CALL_NOT_IMPLEMENTED      =     120_u32
      private ERROR_SERVICE_SPECIFIC_ERROR    =    1066_u32
      private ERROR_FAILED_SERVICE_CONTROLLER =    1063_i64
      private ERROR_SERVICE_DOES_NOT_EXIST    =    1060_u32
      private ERROR_SERVICE_NOT_ACTIVE        =    1062_u32
      private SC_MANAGER_CONNECT              =     0x1_u32
      private SC_MANAGER_CREATE_SERVICE       =     0x2_u32
      private SERVICE_ALL_ACCESS              = 0xF01FF_u32
      private SERVICE_QUERY_STATUS            =     0x4_u32
      private SERVICE_START                   =    0x10_u32
      private SERVICE_STOP                    =    0x20_u32
      private DELETE                          = 0x10000_u32
      private SC_STATUS_PROCESS_INFO          =       0_u32
      private SERVICE_CONFIG_DESCRIPTION      =       1_u32
      private SERVICE_CONFIG_FAILURE_ACTIONS  =       2_u32
      private SC_ACTION_RESTART               =       1_u32

      # State the SCM's threads read and write. Numeric literals only: they are initialised statically, so reading them
      # on a foreign thread runs no Crystal initialiser.
      @@status_handle = 0_u64
      @@name_address = 0_u64
      @@started_write = 0_u64
      @@stop_write = 0_u64
      @@stop_requested = 0
      @@stop_wait_hint_ms = 30_000_u32
      @@check_point = 0_u32
      @@running = false

      # Runs the block as this program's service: connects to the SCM (the program must have been started by it), reports
      # RUNNING, yields, then reports STOPPED. An exception from the block is reported as a service-specific error (so
      # the SCM's failure actions apply) and re-raised. *stop_wait_hint* is what the SCM is told to wait after a stop
      # request before it considers the service hung.
      #
      # Raises `Error::Unavailable` when the program was not started by the SCM (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT).
      def self.run(name : String, *, start_timeout : Time::Span = 30.seconds,
                   stop_wait_hint : Time::Span = 30.seconds, & : Service ->) : Nil
        raise Error::Busy.new("a service is already running in this process") if @@running
        @@running = true
        @@stop_requested = 0
        @@check_point = 0_u32
        @@stop_wait_hint_ms = stop_wait_hint.total_milliseconds.to_u32
        name_w = name.to_utf16
        name_z = Slice(UInt16).new(name_w.size + 1)
        name_w.copy_to(name_z)
        @@name_address = name_z.to_unsafe.address

        started_read, started_write = IO.pipe(read_blocking: false, write_blocking: true)
        stop_read, stop_write = IO.pipe(read_blocking: false, write_blocking: true)
        @@started_write = started_write.fd.to_u64
        @@stop_write = stop_write.fd.to_u64
        dispatch_error = 0_u32

        dispatcher = Fiber::ExecutionContext::Isolated.new("process-supervision-scm-dispatcher") do
          table = StaticArray(LibService::SERVICE_TABLE_ENTRYW, 2).new(LibService::SERVICE_TABLE_ENTRYW.new)
          entry = LibService::SERVICE_TABLE_ENTRYW.new
          entry.name = name_z.to_unsafe
          entry.proc = ->(argc : UInt32, argv : UInt16**) { Service.service_main }
          table[0] = entry
          if LibService.StartServiceCtrlDispatcherW(table.to_unsafe) == 0
            dispatch_error = LibC.GetLastError
            Service.write_byte(Service.started_write_handle, 'F'.ord.to_u8)
          end
        end

        begin
          started_read.read_timeout = start_timeout
          signal = begin
            started_read.read_byte
          rescue IO::TimeoutError
            nil
          end
          unless signal == 'S'.ord
            dispatcher.wait if signal == 'F'.ord
            if dispatch_error.to_i64 == ERROR_FAILED_SERVICE_CONTROLLER
              raise Error::Unavailable.new("not started by the service control manager (StartServiceCtrlDispatcherW: 1063)")
            end
            raise Error::Native.new("StartServiceCtrlDispatcherW",
              signal ? WinError.new(dispatch_error).message : "ServiceMain was not called within #{start_timeout}",
              dispatch_error.to_i64)
          end

          service = new(name, stop_read)
          failure = nil.as(Exception?)
          begin
            yield service
          rescue ex
            failure = ex
          end
          if failure
            report(State::Stopped.value, 0_u32, ERROR_SERVICE_SPECIFIC_ERROR, 1_u32)
          else
            report(State::Stopped.value)
          end
          dispatcher.wait
          raise failure if failure
        ensure
          @@running = false
          @@status_handle = 0_u64
          @@started_write = 0_u64
          @@stop_write = 0_u64
          {started_read, started_write, stop_read, stop_write}.each { |io| io.close rescue nil }
        end
      end

      getter name : String

      private def initialize(@name : String, @stop_read : IO::FileDescriptor)
      end

      # Waits until the SCM asks the service to stop (STOP, or SHUTDOWN at system shutdown). Returns false on timeout.
      def wait_for_stop(timeout : Time::Span? = nil) : Bool
        return true if stop_requested?
        @stop_read.read_timeout = timeout
        @stop_read.read_byte
        true
      rescue IO::TimeoutError
        false
      end

      def stop_requested? : Bool
        @@stop_requested != 0
      end

      # Tells the SCM the stop is still progressing and to wait another *wait_hint* (a long shutdown must call this, or
      # the SCM reports the service as hung once the previous hint has passed).
      def report_stop_progress(wait_hint : Time::Span) : Nil
        @@check_point += 1
        Service.report(State::StopPending.value, wait_hint.total_milliseconds.to_u32, 0_u32, 0_u32, @@check_point)
      end

      # :nodoc:
      def self.started_write_handle : UInt64
        @@started_write
      end

      # :nodoc:
      # Called by the SCM on its own thread: Win32 calls and statically initialised class variables only.
      def self.service_main : Nil
        handler = ->(control : UInt32, event_type : UInt32, event_data : Void*, context : Void*) do
          Service.handle_control(control)
        end
        @@status_handle = LibService.RegisterServiceCtrlHandlerExW(Pointer(UInt16).new(@@name_address), handler, Pointer(Void).null).address
        if @@status_handle == 0
          write_byte(@@started_write, 'F'.ord.to_u8)
          return
        end
        report(State::Running.value)
        write_byte(@@started_write, 'S'.ord.to_u8)
      end

      # :nodoc:
      def self.handle_control(control : UInt32) : UInt32
        case control
        when SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN
          if @@stop_requested == 0
            @@stop_requested = 1
            report(State::StopPending.value, @@stop_wait_hint_ms)
            write_byte(@@stop_write, 1_u8)
          end
          0_u32
        when SERVICE_CONTROL_INTERROGATE
          0_u32
        else
          ERROR_CALL_NOT_IMPLEMENTED
        end
      end

      # :nodoc:
      def self.write_byte(handle : UInt64, byte : UInt8) : Nil
        return if handle == 0
        value = byte
        written = 0_u32
        LibC.WriteFile(LibC::HANDLE.new(handle), pointerof(value).as(Void*), 1_u32, pointerof(written), Pointer(LibC::OVERLAPPED).null)
      end

      # :nodoc:
      def self.report(state : UInt32, wait_hint : UInt32 = 0_u32, exit_code : UInt32 = 0_u32,
                      specific : UInt32 = 0_u32, check_point : UInt32 = 0_u32) : Nil
        return if @@status_handle == 0
        status = LibService::SERVICE_STATUS.new
        status.service_type = SERVICE_WIN32_OWN_PROCESS
        status.current_state = state
        status.controls_accepted = state == State::Running.value ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0_u32
        status.win32_exit_code = exit_code
        status.specific_exit_code = specific
        status.wait_hint = wait_hint
        status.check_point = check_point
        LibService.SetServiceStatus(Pointer(Void).new(@@status_handle), pointerof(status))
      end

      # --- managing services (needs an elevated caller) ---

      # Creates an own-process service running *binary* with *args* (quoted for the C runtime). With
      # *restart_after*, the SCM restarts the service that long after it crashes or reports a service-specific error.
      def self.install(name : String, binary : String, args : Enumerable(String) = [] of String, *,
                       display_name : String = name, description : String? = nil,
                       start_type : StartType = StartType::Demand, restart_after : Time::Span? = nil) : Nil
        command_line = Process.quote_windows([binary] + args.to_a)
        with_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE) do |manager|
          service = LibService.CreateServiceW(manager, wide(name), wide(display_name), SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, start_type.value, 1_u32, wide(command_line), nil, nil, nil, nil, nil)
          raise native_error("CreateServiceW") if service.null?
          begin
            if text = description
              info = LibService::SERVICE_DESCRIPTIONW.new
              info.description = wide(text)
              LibService.ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, pointerof(info).as(Void*))
            end
            if delay = restart_after
              action = LibService::SC_ACTION.new
              action.type = SC_ACTION_RESTART
              action.delay = delay.total_milliseconds.to_u32
              actions = StaticArray(LibService::SC_ACTION, 3).new(action)
              failure = LibService::SERVICE_FAILURE_ACTIONSW.new
              failure.reset_period = 86_400_u32
              failure.actions_count = 3_u32
              failure.actions = actions.to_unsafe
              if LibService.ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, pointerof(failure).as(Void*)) == 0
                raise native_error("ChangeServiceConfig2W(FAILURE_ACTIONS)")
              end
            end
          ensure
            LibService.CloseServiceHandle(service)
          end
        end
      end

      # Deletes the service (it disappears once it is stopped and every handle to it is closed). Returns false if it
      # did not exist.
      def self.uninstall(name : String) : Bool
        with_service(name, DELETE) do |service|
          return false if service.null?
          raise native_error("DeleteService") if LibService.DeleteService(service) == 0
          true
        end
      end

      def self.start(name : String) : Nil
        with_service(name, SERVICE_START) do |service|
          raise Error::Unavailable.new("service #{name} does not exist") if service.null?
          raise native_error("StartServiceW") if LibService.StartServiceW(service, 0_u32, nil) == 0
        end
      end

      # Sends STOP and waits until the service reports STOPPED. Returns false if it did not within *timeout* (a hung
      # STOP handler blocks `ControlService` itself for up to the SCM's pipe timeout, 240 s on the hosted runners).
      def self.stop(name : String, timeout : Time::Span = 30.seconds) : Bool
        with_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS) do |service|
          raise Error::Unavailable.new("service #{name} does not exist") if service.null?
          status = LibService::SERVICE_STATUS.new
          if LibService.ControlService(service, SERVICE_CONTROL_STOP, pointerof(status)) == 0
            error = LibC.GetLastError
            raise native_error("ControlService(STOP)", error) unless error == ERROR_SERVICE_NOT_ACTIVE
          end
        end
        deadline = Time.instant + timeout
        loop do
          return true if state(name).in?(nil, State::Stopped)
          return false if Time.instant >= deadline
          sleep 20.milliseconds
        end
      end

      # The service's state, or nil if it does not exist.
      def self.state(name : String) : State?
        query(name).try { |status| State.from_value(status.current_state) }
      end

      # The process running the service, or nil when it is not running or does not exist.
      def self.process_id(name : String) : Int64?
        query(name).try { |status| status.process_id == 0 ? nil : status.process_id.to_i64 }
      end

      private def self.query(name : String) : LibService::SERVICE_STATUS_PROCESS?
        with_service(name, SERVICE_QUERY_STATUS) do |service|
          return nil if service.null?
          status = LibService::SERVICE_STATUS_PROCESS.new
          needed = 0_u32
          if LibService.QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, pointerof(status).as(UInt8*),
               sizeof(LibService::SERVICE_STATUS_PROCESS).to_u32, pointerof(needed)) == 0
            raise native_error("QueryServiceStatusEx")
          end
          status
        end
      end

      private def self.with_manager(access : UInt32, &)
        manager = LibService.OpenSCManagerW(nil, nil, access)
        raise native_error("OpenSCManagerW") if manager.null?
        begin
          yield manager
        ensure
          LibService.CloseServiceHandle(manager)
        end
      end

      # Yields the opened service, or a null pointer when it does not exist.
      private def self.with_service(name : String, access : UInt32, &)
        manager = LibService.OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT)
        raise native_error("OpenSCManagerW") if manager.null?
        handle = LibService.OpenServiceW(manager, wide(name), access)
        if handle.null?
          error = LibC.GetLastError
          LibService.CloseServiceHandle(manager)
          raise native_error("OpenServiceW", error) unless error == ERROR_SERVICE_DOES_NOT_EXIST
          return yield Pointer(Void).null
        end
        begin
          yield handle
        ensure
          LibService.CloseServiceHandle(handle)
          LibService.CloseServiceHandle(manager)
        end
      end

      private def self.wide(text : String) : UInt16*
        units = text.to_utf16
        buffer = Slice(UInt16).new(units.size + 1)
        units.copy_to(buffer)
        buffer.to_unsafe
      end

      private def self.native_error(operation : String, code : UInt32 = LibC.GetLastError) : Error::Native
        Error::Native.new(operation, WinError.new(code).message, code.to_i64)
      end
    end
  end
{% end %}
