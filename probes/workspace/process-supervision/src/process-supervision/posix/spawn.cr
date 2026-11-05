{% if flag?(:unix) %}
  module ProcessSupervision::POSIX
    # :nodoc:
    #
    # Argument, environment and executable preparation shared by the POSIX spawn engines. Everything that allocates
    # happens here, in the parent, before the process exists: the engines' child side may only make plain system calls.
    #
    # Behaviour measured natively (explore/FINDINGS.md, "Spawning into containment"):
    # * the command is resolved in the caller, before any `chdir`; a name without a slash is searched in the caller's
    #   PATH, a path with a slash is made absolute against the caller's current directory;
    # * the child starts with default signal dispositions and an empty signal mask (the stdlib's `Process.new` passes on
    #   ignored SIGPIPE/SIGHUP; a supervisor should not);
    # * standard streams 0-2 are inherited, nothing else (Crystal opens its descriptors close-on-exec).
    module Spawn
      # NUL-terminated pointer array that keeps its strings alive for as long as it is reachable.
      class CStrings
        @strings : Array(String)
        getter pointers : Pointer(Pointer(UInt8))

        def initialize(list : Array(String))
          @strings = list.map(&.dup)
          @pointers = Pointer(Pointer(UInt8)).malloc(list.size + 1)
          @strings.each_with_index { |string, index| @pointers[index] = string.to_unsafe }
          @pointers[list.size] = Pointer(UInt8).null
        end
      end

      struct Prepared
        getter command : String
        getter path : String
        getter argv : CStrings
        getter envp : CStrings
        getter chdir : String?
        getter options : ProcessSupervision::SpawnOptions
        # this process, for the child's parent-death check
        getter parent_pid : Int32
        # flat {resource, soft, hard} triples for the child's setrlimit calls (allocated here, read in the child)
        getter rlimits : Pointer(UInt64)
        getter rlimit_count : Int32
        getter groups : Pointer(UInt32)
        getter group_count : Int32
        # descriptor number of the child's IPC socket, or -1
        getter ipc_target : Int32

        def initialize(@command : String, @path : String, @argv : CStrings, @envp : CStrings, @chdir : String?,
                       @options : ProcessSupervision::SpawnOptions = ProcessSupervision::SpawnOptions.new,
                       @ipc_target : Int32 = -1)
          @parent_pid = LibC.getpid
          @rlimit_count = @options.rlimits.size
          @rlimits = Pointer(UInt64).malloc({@rlimit_count * 3, 1}.max)
          @options.rlimits.each_with_index do |(resource, limits), index|
            @rlimits[index * 3] = resource.native.to_u64
            @rlimits[index * 3 + 1] = limits[0]
            @rlimits[index * 3 + 2] = limits[1]
          end
          list = @options.groups || [] of UInt32
          @group_count = list.size
          @groups = Pointer(UInt32).malloc({@group_count, 1}.max)
          list.each_with_index { |value, index| @groups[index] = value }
        end
      end

      # *marker* is an extra `NAME=value` entry (a process group's descendant marker) that survives `clear_env`.
      def self.prepare(command : String, args : Enumerable(String), env : ::Process::Env,
                       clear_env : Bool, chdir : Path | String?, marker : String? = nil,
                       options : ProcessSupervision::SpawnOptions = ProcessSupervision::SpawnOptions.new) : Prepared
        validate_text!(command, "command")
        raise ArgumentError.new("command must not be empty") if command.empty?
        argv = [command]
        args.each_with_index do |arg, index|
          validate_text!(arg, "argument #{index}")
          argv << arg
        end
        directory = chdir.try(&.to_s)
        directory.try { |value| validate_text!(value, "chdir") }
        entries = environment(env, clear_env)
        if marker
          name = marker.split('=', 2).first
          entries.reject!(&.starts_with?("#{name}="))
          entries << marker
        end
        ipc_target = -1
        if options.ipc
          ipc_target = 3
          while options.extra_fds.has_key?(ipc_target)
            ipc_target += 1
          end
          entries.reject!(&.starts_with?("PROCESS_SUPERVISION_IPC_FD="))
          entries << "PROCESS_SUPERVISION_IPC_FD=#{ipc_target}"
        end
        Prepared.new(command, resolve(command), CStrings.new(argv), CStrings.new(entries), directory, options, ipc_target)
      end

      # Resolves in the caller so that the result does not depend on the child's working directory.
      def self.resolve(command : String) : String
        if command.includes?('/')
          Path.new(command).expand.to_s
        else
          found = ::Process.find_executable(command)
          raise ::File::Error.from_os_error("Error executing process", Errno::ENOENT, file: command) unless found
          Path.new(found).expand.to_s
        end
      end

      def self.environment(env : ::Process::Env, clear_env : Bool) : Array(String)
        values = {} of String => String
        ENV.each { |key, value| values[key] = value } unless clear_env
        env.try &.each do |key, value|
          raise ArgumentError.new("Invalid env key #{key.inspect}") if key.empty? || key.includes?('=')
          validate_text!(key, "env key")
          if value
            validate_text!(value, "env value")
            values[key] = value
          else
            values.delete(key)
          end
        end
        values.map { |key, value| "#{key}=#{value}" }
      end

      # Standard-stream plumbing for one spawn. `build` creates the pipes and descriptor copies; the engines dup2 the
      # `sources` onto 0-2 in the child; `release_child_side` must run right after the process exists (the parent must not
      # keep the child's ends open or the other side never sees EOF); `abandon` also closes the parent's ends.
      #
      # Supported: Process::Redirect::Inherit / Close (the null device) / Pipe, an IO::FileDescriptor (a File, STDOUT), and
      # any other IO, which gets a pipe and a copy fiber (`copies`, started by Child); a closed IO gets the null device.
      # Every source is copied to a descriptor above every target (3 and up, and above the highest extra descriptor), so
      # that no dup2 in the child can overwrite a source it still needs (a closed stdin makes pipe() return 0).
      #
      # Extra descriptors (`SpawnOptions#extra_fds`, the IPC socket) are further {target, source} pairs (`extra_targets`,
      # `extra_sources`, `extra_count`: plain memory the child side can read without allocating).
      class Plumbing
        getter sources = StaticArray(Int32, 3).new(-1)
        getter extra_targets = Pointer(Int32).malloc(16)
        getter extra_sources = Pointer(Int32).malloc(16)
        getter extra_count = 0
        getter ipc : ::UNIXSocket? = nil
        @minimum = 3
        @child_sockets = [] of ::UNIXSocket
        getter input : IO::FileDescriptor? = nil
        getter output : IO::FileDescriptor? = nil
        getter error : IO::FileDescriptor? = nil
        getter copies = ProcessSupervision::StreamCopies.new

        @child_ends = [] of IO::FileDescriptor
        @copies_fds = [] of Int32

        def self.build(input : ::Process::Stdio, output : ::Process::Stdio, error : ::Process::Stdio,
                       options : ProcessSupervision::SpawnOptions = ProcessSupervision::SpawnOptions.new,
                       ipc_target : Int32 = -1) : Plumbing
          plumbing = new
          plumbing.copies.wait_delay = options.wait_delay
          begin
            plumbing.reserve_above((options.extra_fds.keys + [ipc_target]).max? || 2)
            plumbing.add(0, input)
            plumbing.add(1, output)
            plumbing.add(2, error)
            options.extra_fds.each { |target, io| plumbing.add_extra(target, io) }
            plumbing.add_ipc(ipc_target) if ipc_target >= 3
          rescue ex
            plumbing.abandon
            raise ex
          end
          plumbing
        end

        def self.inherit : Plumbing
          new
        end

        protected def reserve_above(highest_target : Int32) : Nil
          @minimum = {3, highest_target + 1}.max
        end

        def add_extra(target : Int32, io : IO::FileDescriptor) : Nil
          raise ArgumentError.new("too many extra descriptors (16 at most)") if @extra_count >= 16
          @extra_targets[@extra_count] = target
          @extra_sources[@extra_count] = duplicate_above_stdio(io.fd)
          @extra_count += 1
        end

        def add_ipc(target : Int32) : Nil
          parent_end, child_end = ::UNIXSocket.pair
          # O_NONBLOCK belongs to the open socket, which the child would share: its end must block (the parent's is a
          # separate socket of the pair and stays non-blocking for the event loop)
          IO::FileDescriptor.set_blocking(child_end.fd, true)
          @ipc = parent_end
          @child_sockets << child_end
          raise ArgumentError.new("too many extra descriptors (16 at most)") if @extra_count >= 16
          @extra_targets[@extra_count] = target
          @extra_sources[@extra_count] = duplicate_above_stdio(child_end.fd)
          @extra_count += 1
        end

        def add(target : Int32, spec : ::Process::Stdio) : Nil
          case spec
          when ::Process::Redirect
            case spec
            when .inherit?
              # keep the parent's descriptor
            when .close?
              null_device(target)
            when .pipe?
              parent_end = pipe(target)
              case target
              when 0 then @input = parent_end
              when 1 then @output = parent_end
              else        @error = parent_end
              end
            end
          when IO::FileDescriptor
            @sources[target] = duplicate_above_stdio(spec.fd)
          else
            if spec.closed?
              null_device(target)
            elsif target == 0
              @copies.add_input(spec, pipe(target))
            else
              @copies.add_output(pipe(target), spec)
            end
          end
        end

        private def null_device(target : Int32) : Nil
          fd = LibC.open("/dev/null", LibC::O_RDWR | LibC::O_CLOEXEC)
          raise native_error("open(/dev/null)") if fd < 0
          @copies_fds << fd
          @sources[target] = fd
        end

        # A pipe for stream *target*: the child's end (blocking) becomes its source, the parent's end (non-blocking) is
        # returned.
        private def pipe(target : Int32) : IO::FileDescriptor
          if target == 0
            reader, writer = IO.pipe(read_blocking: true, write_blocking: false)
            @child_ends << reader
            @sources[target] = movable(reader)
            writer
          else
            reader, writer = IO.pipe(read_blocking: false, write_blocking: true)
            @child_ends << writer
            @sources[target] = movable(writer)
            reader
          end
        end

        def release_child_side : Nil
          @child_ends.each { |io| io.close rescue nil }
          @child_ends.clear
          @copies_fds.each { |fd| LibC.close(fd) }
          @copies_fds.clear
          @child_sockets.each { |socket| socket.close rescue nil }
          @child_sockets.clear
        end

        def abandon : Nil
          release_child_side
          {@input, @output, @error}.each { |io| io.try { |stream| stream.close rescue nil } }
          @ipc.try { |socket| socket.close rescue nil }
          @copies.close
        end

        private def movable(io : IO::FileDescriptor) : Int32
          io.fd >= @minimum ? io.fd : duplicate_above_stdio(io.fd)
        end

        private def duplicate_above_stdio(fd : Int32) : Int32
          copy = LibC.fcntl(fd, F_DUPFD_CLOEXEC, @minimum)
          raise native_error("fcntl(F_DUPFD_CLOEXEC)") if copy < 0
          @copies_fds << copy
          copy
        end

        private def native_error(operation : String) : Exception
          errno = Errno.value
          ProcessSupervision::Error::Native.new(operation, errno.message, errno.value.to_i64)
        end
      end

      F_DUPFD_CLOEXEC = {% if flag?(:darwin) %}67{% else %}1030{% end %}

      # The stdlib's classification of a failed exec, so callers see the same exception classes as for Process.new.
      def self.exec_error(command : String, errno : Errno) : Exception
        if ::File::NotFoundError.os_error?(errno) || ::File::AccessDeniedError.os_error?(errno) || errno == Errno::ENOEXEC
          ::File::Error.from_os_error("Error executing process", errno, file: command)
        else
          ::IO::Error.from_os_error("Error executing process: '#{command}'", errno)
        end
      end

      # Hands a pid created outside Process.new to Crystal's child reaper. The runtime already reaps every child and keeps
      # the status of pids nobody waits for yet, so this may happen after the child exited; do not waitpid it yourself.
      #
      # Before handing it over, drops a status the runtime parked under this pid for an earlier, *different* child (see
      # `Crystal::System::SignalChildHandler.discard_stale_status`): `Crystal::System::Process.new` claims a parked status
      # at once, so a stray's status would otherwise become this child's.
      def self.adopt(pid : Int32) : ::Process
        Crystal::System::SignalChildHandler.discard_stale_status(pid)
        ::Process.new(Crystal::System::Process.new(pid))
      end

      # Whether *pid* (a child of this process) has been reaped already: `waitid(P_PID, WNOHANG | WNOWAIT)` answers
      # ECHILD for a reaped pid, and leaves a running or zombie child untouched.
      def self.reaped?(pid : Int32) : Bool
        info = uninitialized UInt8[128]
        {% if flag?(:darwin) %}
          options = 0x04 | 0x01 | 0x20 # WEXITED | WNOHANG | WNOWAIT
        {% else %}
          options = 0x04 | 0x01 | 0x01000000
        {% end %}
        LibProcessSupervisionWaitid.waitid(1, pid.to_u32, info.to_unsafe.as(Void*), options) != 0 && Errno.value == Errno::ECHILD
      end

      private def self.validate_text!(value : String, label : String) : Nil
        raise ArgumentError.new("Invalid #{label}: contains NUL byte") if value.includes?('\0')
      end
    end
  end
{% end %}

{% if flag?(:unix) %}
  private lib LibProcessSupervisionWaitid
    fun waitid(idtype : Int32, id : UInt32, info : Void*, options : Int32) : Int32
  end

  # Crystal's SIGCHLD handler (stdlib internal, Crystal 1.21) reaps every child with `waitpid(-1)` and parks the status
  # of a pid nobody waits for yet. A stray child (an orphan adopted as a subreaper, a raw fork, a `Process` dropped
  # without `wait`) leaves such an entry, and when the kernel reuses that pid, `Process.new`'s internal
  # `SignalChildHandler.wait` claims the stray's status for the new child (measured: a child that ran for a second
  # "exited 7" after 2 ms; spec "never reports a stray child's parked status").
  module Crystal::System::SignalChildHandler
    # :nodoc:
    #
    # Drops the parked status for *pid* unless the current child with that pid has itself been reaped (then the
    # handler has overwritten the entry with its real status). Checked under the handler's mutex: the handler reaps
    # before it takes the mutex, so a reap racing this check either is seen as ECHILD (and its status stored after) or
    # stores its status after the stale one was dropped.
    def self.discard_stale_status(pid : LibC::PidT) : Nil
      @@mutex.lock
      begin
        if @@pending.has_key?(pid) && !ProcessSupervision::POSIX::Spawn.reaped?(pid)
          @@pending.delete(pid)
        end
      ensure
        @@mutex.unlock
      end
    end
  end
{% end %}
