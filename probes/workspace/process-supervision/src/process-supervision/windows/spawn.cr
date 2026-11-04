{% if flag?(:win32) %}
  module ProcessSupervision::Windows
    class Job
      # Internal adapter for adopting Crystal's already-created low-level child
      # owner after the native spawn transaction has established containment.
      private class SpawnedProcess < ::Process
        def self.wrap(info : Crystal::System::Process) : ::Process
          new(info)
        end
      end

      # Spawns a direct executable/argv child already contained by this Job
      # before its initial thread can run. The Job-list creation attribute closes
      # the owner-death gap; CREATE_SUSPENDED plus an explicit assignment check
      # prevents the child from creating descendants before membership is
      # confirmed.
      #
      # Standard streams are inherited explicitly through a HANDLE allow-list;
      # no unrelated inheritable handles are admitted. Batch files are rejected
      # because direct CreateProcessW execution implicitly invokes cmd.exe.
      def spawn(command : String, args : Enumerable(String) = [] of String, *,
                env : Process::Env = nil, clear_env : Bool = false,
                chdir : Path | String? = nil) : ProcessSupervision::Child
        run_on_execution_context("process-supervision-windows-job-spawn") do
          spawn_on_execution_context(command, args, env: env, clear_env: clear_env, chdir: chdir)
        end
      end

      private def spawn_on_execution_context(command : String, args : Enumerable(String), *,
                                             env : Process::Env, clear_env : Bool,
                                             chdir : Path | String?) : ProcessSupervision::Child
        validate_no_nul!(command, "command")
        reject_batch_file(command)
        argv = [command]
        args.each_with_index do |arg, index|
          validate_no_nul!(arg, "argument #{index}")
          argv << arg
        end
        chdir_string = chdir.try &.to_s
        chdir_string.try { |path| validate_no_nul!(path, "chdir") }
        env_entries = materialize_environment(env)
        env_block = build_environment(env_entries, clear_env)

        command_line = Process.quote_windows(argv).to_utf16
        chdir_w = chdir_string.try &.to_utf16

        std_input = LibC::HANDLE.null
        std_output = LibC::HANDLE.null
        std_error = LibC::HANDLE.null
        attr_storage = nil.as(Bytes?)
        attr_initialized = false
        process_info = LibC::PROCESS_INFORMATION.new
        process_created = false
        process_transferred = false
        stable_handle = nil.as(ProcessHandle?)

        begin
          std_input = Native.standard_handle(Native::STD_INPUT_HANDLE, input: true)
          std_output = Native.standard_handle(Native::STD_OUTPUT_HANDLE, input: false)
          std_error = Native.standard_handle(Native::STD_ERROR_HANDLE, input: false)
          inherited = StaticArray[std_input, std_output, std_error]

          attr_bytes = LibC::SizeT.new(0)
          NativeLib.InitializeProcThreadAttributeList(Pointer(Void).null, 2_u32, 0_u32, pointerof(attr_bytes))
          raise Native.error("InitializeProcThreadAttributeList(size)") if attr_bytes == 0
          attr_storage = Bytes.new(attr_bytes.to_i)
          attr_list = attr_storage.to_unsafe.as(Void*)
          if NativeLib.InitializeProcThreadAttributeList(attr_list, 2_u32, 0_u32, pointerof(attr_bytes)) == 0
            raise Native.error("InitializeProcThreadAttributeList")
          end
          attr_initialized = true

          startup = StartupInfoExW.new
          startup.startup_info.cb = sizeof(StartupInfoExW).to_u32
          startup.startup_info.dwFlags = Native::STARTF_USESTDHANDLES
          startup.startup_info.hStdInput = std_input
          startup.startup_info.hStdOutput = std_output
          startup.startup_info.hStdError = std_error
          startup.attribute_list = attr_list

          @mutex.synchronize do
            job_handle = checked_handle
            if NativeLib.UpdateProcThreadAttribute(
                 attr_list, 0_u32, Native::PROC_THREAD_ATTRIBUTE_JOB_LIST,
                 pointerof(job_handle).as(Void*), LibC::SizeT.new(sizeof(LibC::HANDLE)),
                 Pointer(Void).null, Pointer(LibC::SizeT).null
               ) == 0
              raise Native.error("UpdateProcThreadAttribute(JOB_LIST)")
            end

            if NativeLib.UpdateProcThreadAttribute(
                 attr_list, 0_u32, Native::PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                 inherited.to_unsafe.as(Void*), LibC::SizeT.new(sizeof(LibC::HANDLE) * inherited.size),
                 Pointer(Void).null, Pointer(LibC::SizeT).null
               ) == 0
              raise Native.error("UpdateProcThreadAttribute(HANDLE_LIST)")
            end

            flags = Native::EXTENDED_STARTUPINFO_PRESENT |
                    Native::CREATE_UNICODE_ENVIRONMENT |
                    Native::CREATE_SUSPENDED

            if LibC.CreateProcessW(
                 Pointer(UInt16).null,
                 command_line.to_unsafe,
                 Pointer(LibC::SECURITY_ATTRIBUTES).null,
                 Pointer(LibC::SECURITY_ATTRIBUTES).null,
                 1,
                 flags,
                 env_block.to_unsafe.as(Void*),
                 chdir_w.try(&.to_unsafe) || Pointer(UInt16).null,
                 pointerof(startup).as(LibC::STARTUPINFOW*),
                 pointerof(process_info)
               ) == 0
              raise Native.error("CreateProcessW(supervised child)")
            end
            process_created = true

            # The attribute is the atomic containment mechanism. This explicit
            # assignment is a verification/backstop while the thread is still
            # suspended; assigning a process already in this Job is valid.
            if LibC.AssignProcessToJobObject(job_handle, process_info.hProcess) == 0
              raise Native.error("AssignProcessToJobObject(supervised child)")
            end
          end

          generation = Native.process_creation_time(process_info.hProcess, "GetProcessTimes(supervised child)")
          stable_handle = ProcessHandle.open(process_info.dwProcessId.to_i64)
          unless stable_handle.identity.generation == generation
            raise ProcessSupervision::Error::Native.new(
              "ProcessHandle.open(supervised child)",
              "process identity changed before resume"
            )
          end

          # Crystal's low-level Windows Process constructor owns the process
          # HANDLE, resumes the initial thread exactly once, and closes the
          # thread HANDLE. Containment is already established at this point.
          system_process = Crystal::System::Process.new(process_info)
          process_transferred = true
          process = SpawnedProcess.wrap(system_process)
          ProcessSupervision::Child.new(process, stable_handle, self)
        rescue ex
          stable_handle.try do |handle|
            handle.close rescue nil
          end
          if process_created && !process_transferred
            LibC.TerminateProcess(process_info.hProcess, 125_u32) unless process_info.hProcess.null?
          end
          raise ex
        ensure
          if process_created && !process_transferred
            Native.close_native_handle(process_info.hThread)
            Native.close_native_handle(process_info.hProcess)
          end
          if attr_initialized && (storage = attr_storage)
            NativeLib.DeleteProcThreadAttributeList(storage.to_unsafe.as(Void*))
          end
          Native.close_native_handle(std_input)
          Native.close_native_handle(std_output)
          Native.close_native_handle(std_error)
        end
      end

      private def build_environment(env : Array(Tuple(String, String?))?, clear_env : Bool) : Slice(UInt16)
        values = {} of String => String
        reserved = [] of String
        unless clear_env
          ENV.each { |key, value| values[key] = value }
          reserved = Native.reserved_environment_entries
        end

        env.try &.each do |key, value|
          set_environment_value(values, key, value)
        end

        units = [] of UInt16
        reserved.each do |entry|
          entry.to_utf16.each { |unit| units << unit }
          units << 0_u16
        end
        values.to_a.sort_by { |(key, _)| key.downcase }.each do |key, value|
          validate_environment_key!(key)
          validate_no_nul!(value, "env value")
          "#{key}=#{value}".to_utf16.each { |unit| units << unit }
          units << 0_u16
        end
        units << 0_u16 if units.empty?
        units << 0_u16
        Slice(UInt16).new(units.size) { |index| units[index] }
      end

      private def materialize_environment(env : Process::Env) : Array(Tuple(String, String?))?
        env.try do |source|
          entries = [] of Tuple(String, String?)
          source.each do |key, value|
            validate_environment_key!(key)
            validate_no_nul!(value, "env value") if value
            entries << {key, value}
          end
          entries
        end
      end

      private def set_environment_value(values : Hash(String, String), key : String, value : String?) : Nil
        validate_environment_key!(key)
        validate_no_nul!(value, "env value") if value
        existing = values.keys.find { |candidate| candidate.compare(key, case_insensitive: true) == 0 }
        values.delete(existing) if existing
        values[key] = value if value
      end

      private def validate_environment_key!(key : String) : Nil
        raise ArgumentError.new("Invalid env key #{key.inspect}") if key.empty? || key.includes?('=')
        validate_no_nul!(key, "env key")
      end

      private def validate_no_nul!(value : String, label : String) : Nil
        raise ArgumentError.new("Invalid #{label}: contains NUL byte") if value.includes?('\0')
      end

      private def reject_batch_file(command : String) : Nil
        trimmed = command.rstrip(". ").downcase
        if trimmed.ends_with?(".bat") || trimmed.ends_with?(".cmd")
          raise ProcessSupervision::Error::Unsupported.new(
            "direct batch-file execution is unsupported; invoke cmd.exe explicitly"
          )
        end
      end
    end
  end
{% end %}
