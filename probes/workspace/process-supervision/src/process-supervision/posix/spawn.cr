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

        def initialize(@command : String, @path : String, @argv : CStrings, @envp : CStrings, @chdir : String?)
        end
      end

      def self.prepare(command : String, args : Enumerable(String), env : ::Process::Env,
                       clear_env : Bool, chdir : Path | String?) : Prepared
        validate_text!(command, "command")
        raise ArgumentError.new("command must not be empty") if command.empty?
        argv = [command]
        args.each_with_index do |arg, index|
          validate_text!(arg, "argument #{index}")
          argv << arg
        end
        directory = chdir.try(&.to_s)
        directory.try { |value| validate_text!(value, "chdir") }
        Prepared.new(command, resolve(command), CStrings.new(argv), CStrings.new(environment(env, clear_env)), directory)
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
      def self.adopt(pid : Int32) : ::Process
        ::Process.new(Crystal::System::Process.new(pid))
      end

      private def self.validate_text!(value : String, label : String) : Nil
        raise ArgumentError.new("Invalid #{label}: contains NUL byte") if value.includes?('\0')
      end
    end
  end
{% end %}
