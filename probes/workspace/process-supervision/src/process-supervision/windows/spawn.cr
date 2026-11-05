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
      # Standard streams reach the child through a HANDLE allow-list; no
      # unrelated inheritable handles are admitted. Each of *input*, *output*
      # and *error* is `Process::Redirect::Inherit` (the default: the parent's
      # standard handle, or the null device if it has none), `Close` (the null
      # device), `Pipe` (read or write it through `Child#input` / `#output` /
      # `#error`, closed by `Child#close`), an `IO::FileDescriptor` such as a
      # `File`, or any other `IO`, which gets a pipe and a copy fiber (as does a
      # file opened for overlapped I/O, which a child cannot use directly).
      # Batch files are rejected because direct CreateProcessW execution
      # implicitly invokes cmd.exe.
      def spawn(command : String, args : Enumerable(String) = [] of String, *,
                env : Process::Env = nil, clear_env : Bool = false,
                chdir : Path | String? = nil,
                input : ::Process::Stdio = ::Process::Redirect::Inherit,
                output : ::Process::Stdio = ::Process::Redirect::Inherit,
                error : ::Process::Stdio = ::Process::Redirect::Inherit,
                options : ProcessSupervision::SpawnOptions = ProcessSupervision::SpawnOptions.new) : ProcessSupervision::Child
        options.check_supported!("a Windows Job", new_session: false, ipc: false, console_group: true, hide_window: true)
        run_on_execution_context("process-supervision-windows-job-spawn") do
          spawn_on_execution_context(command, args, env: env, clear_env: clear_env, chdir: chdir,
            input: input, output: output, error: error, options: options)
        end
      end

      # The longest command line CreateProcessW accepts, in UTF-16 units including the terminator.
      MAX_COMMAND_LINE = 32_767

      private def spawn_on_execution_context(command : String, args : Enumerable(String), *,
                                             env : Process::Env, clear_env : Bool,
                                             chdir : Path | String?,
                                             input : ::Process::Stdio, output : ::Process::Stdio,
                                             error : ::Process::Stdio,
                                             options : ProcessSupervision::SpawnOptions) : ProcessSupervision::Child
        validate_no_nul!(command, "command")
        reject_batch_file(command)
        argv = [command]
        args.each_with_index do |arg, index|
          validate_no_nul!(arg, "argument #{index}")
          argv << arg
        end
        chdir_string = chdir.try &.to_s
        chdir_string.try { |path| validate_no_nul!(path, "chdir") }
        command_line = Process.quote_windows(argv).to_utf16
        if command_line.size + 1 > MAX_COMMAND_LINE
          raise ArgumentError.new("command line is #{command_line.size + 1} UTF-16 units; CreateProcessW accepts #{MAX_COMMAND_LINE}")
        end
        chdir_w = chdir_string.try &.to_utf16

        plumbing = nil.as(Plumbing?)
        attr_storage = nil.as(Bytes?)
        attr_initialized = false
        process_info = LibC::PROCESS_INFORMATION.new
        process_created = false
        process_transferred = false
        stable_handle = nil.as(ProcessHandle?)

        begin
          plumbing = Plumbing.build(input, output, error)
          # extra handles: inheritable duplicates the child sees under the same numeric values, announced as
          # PROCESS_SUPERVISION_HANDLES=<requested number>:<handle value>,...
          announced = [] of String
          options.extra_fds.each do |target, io|
            handle = plumbing.add_extra(io)
            announced << "#{target}:#{handle.address}"
          end
          env_entries = materialize_environment(env) || [] of Tuple(String, String?)
          env_entries << {"PROCESS_SUPERVISION_HANDLES", announced.join(',')} unless announced.empty?
          env_block = build_environment(env_entries, clear_env)
          inherited = plumbing.allow_list

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
          startup.startup_info.hStdInput = inherited[0]
          startup.startup_info.hStdOutput = inherited[1]
          startup.startup_info.hStdError = inherited[2]
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
            # its own console process group: CTRL_BREAK_EVENT can then be sent to it alone (request_stop)
            flags |= 0x00000200_u32 if options.console_group # CREATE_NEW_PROCESS_GROUP
            flags |= 0x08000000_u32 if options.hide_window   # CREATE_NO_WINDOW

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

          # The child holds its own copies now (outside the Job mutex: closing an
          # IO may yield). The parent must not keep the child's pipe ends open,
          # or the other side never sees EOF.
          plumbing.release_child_side

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
          ProcessSupervision::Child.new(process, stable_handle, self, plumbing.input, plumbing.output, plumbing.error, plumbing.copies)
        rescue ex
          stable_handle.try do |handle|
            handle.close rescue nil
          end
          plumbing.try &.abandon
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
          plumbing.try &.release_child_side
        end
      end

      # Standard-stream plumbing for one spawn. `build` makes one inheritable
      # HANDLE per stream (`handles`, the allow-list and STARTUPINFO entries)
      # plus, for `Redirect::Pipe`, a pipe whose parent end is exposed as
      # `input` / `output` / `error`. `release_child_side` closes the
      # inheritable duplicates and the parent's copies of the child's pipe
      # ends; it must run once the process exists. `abandon` also closes the
      # parent's pipe ends.
      #
      # As in the stdlib, the child's end of each pipe is synchronous and the
      # parent's end is overlapped (driven by the event loop). Every stream gets
      # its own duplicate even when two specs name the same HANDLE, so the
      # allow-list never holds a value twice.
      private class Plumbing
        getter handles = StaticArray(LibC::HANDLE, 3).new(LibC::HANDLE.null)
        @extra = [] of LibC::HANDLE

        def add_extra(io : IO::FileDescriptor) : LibC::HANDLE
          handle = Native.duplicate_inheritable(LibC::HANDLE.new(io.fd), "DuplicateHandle(extra handle)")
          @extra << handle
          handle
        end

        # every handle the child may inherit: the three standard ones, then the extra ones
        def allow_list : Array(LibC::HANDLE)
          @handles.to_a + @extra
        end

        getter input : IO::FileDescriptor? = nil
        getter output : IO::FileDescriptor? = nil
        getter error : IO::FileDescriptor? = nil
        getter copies = ProcessSupervision::StreamCopies.new

        @child_ends = [] of IO::FileDescriptor

        def self.build(input : ::Process::Stdio, output : ::Process::Stdio, error : ::Process::Stdio) : Plumbing
          plumbing = new
          begin
            plumbing.add(0, input)
            plumbing.add(1, output)
            plumbing.add(2, error)
          rescue ex
            plumbing.abandon
            raise ex
          end
          plumbing
        end

        def add(target : Int32, spec : ::Process::Stdio) : Nil
          reading = target == 0
          case spec
          when ::Process::Redirect
            case spec
            when .inherit?
              kind = {Native::STD_INPUT_HANDLE, Native::STD_OUTPUT_HANDLE, Native::STD_ERROR_HANDLE}[target]
              @handles[target] = Native.standard_handle(kind, input: reading)
            when .close?
              @handles[target] = Native.null_device(input: reading)
            when .pipe?
              parent_end = pipe(target)
              case target
              when 0 then @input = parent_end
              when 1 then @output = parent_end
              else        @error = parent_end
              end
            end
          when IO::FileDescriptor
            # An overlapped regular file cannot serve a child that does
            # synchronous I/O on it, so it is copied through a pipe like any
            # other IO. Overlapped pipes (an IO.pipe end) are fine as they are.
            if !spec.closed? && (spec.system_blocking? || pipe?(spec))
              @handles[target] = Native.duplicate_inheritable(LibC::HANDLE.new(spec.fd), "DuplicateHandle(standard stream #{target})")
            else
              copy_through_pipe(target, spec)
            end
          else
            copy_through_pipe(target, spec)
          end
        end

        private def copy_through_pipe(target : Int32, io : IO) : Nil
          if io.closed?
            @handles[target] = Native.null_device(input: target == 0)
          elsif target == 0
            @copies.add_input(io, pipe(target))
          else
            @copies.add_output(pipe(target), io)
          end
        end

        # A pipe for stream *target*: the child's end (synchronous) is
        # duplicated into `handles`, the parent's end (overlapped) is returned.
        private def pipe(target : Int32) : IO::FileDescriptor
          if target == 0
            reader, writer = IO.pipe(read_blocking: true, write_blocking: false)
            @child_ends << reader
            @handles[target] = Native.duplicate_inheritable(LibC::HANDLE.new(reader.fd), "DuplicateHandle(stdin pipe)")
            writer
          else
            reader, writer = IO.pipe(read_blocking: false, write_blocking: true)
            @child_ends << writer
            @handles[target] = Native.duplicate_inheritable(LibC::HANDLE.new(writer.fd), "DuplicateHandle(#{target == 1 ? "stdout" : "stderr"} pipe)")
            reader
          end
        end

        def release_child_side : Nil
          @handles.each { |handle| Native.close_native_handle(handle) }
          @extra.each { |handle| Native.close_native_handle(handle) }
          @extra.clear
          @handles = StaticArray(LibC::HANDLE, 3).new(LibC::HANDLE.null)
          @child_ends.each { |io| io.close rescue nil }
          @child_ends.clear
        end

        def abandon : Nil
          release_child_side
          {@input, @output, @error}.each { |io| io.try { |stream| stream.close rescue nil } }
          @copies.close
        end

        private def pipe?(io : IO::FileDescriptor) : Bool
          io.info.type.pipe?
        rescue
          false
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
