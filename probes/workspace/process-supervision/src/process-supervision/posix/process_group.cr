{% if flag?(:unix) %}
  module ProcessSupervision::POSIX
    # Controller for an existing POSIX process group. A process group is not a
    # kernel lifetime container: descendants can call setsid/setpgid and escape,
    # and closing this object cannot kill the group after an abrupt owner death.
    class ProcessGroup < ProcessSupervision::Group
      getter pgid : Int64

      @mutex = Thread::Mutex.new
      @closed = false

      def initialize(@pgid : Int64)
        raise ArgumentError.new("pgid must be positive") unless @pgid > 0
        raise ArgumentError.new("pgid exceeds native pid range") if @pgid > Int32::MAX
        # kill(-1, sig) is not "group 1": it signals every process the caller may signal. Found when the specs ran as
        # PID 1 of a container, whose process group is 1.
        if @pgid == 1
          raise ArgumentError.new("process group 1 cannot be addressed: kill(-1, sig) would signal every process")
        end
      end

      # Spawns a direct executable/argv child into this process group, which must still have a live member in the
      # caller's session. The child starts with default signal dispositions and an empty signal mask, inherits stdio
      # 0-2 and nothing else, and its executable is resolved in the caller before `chdir` takes effect. A process
      # group is not a kill-on-close container: a descendant can still leave it (setsid/setpgid).
      def spawn(command : String, args : Enumerable(String) = [] of String, *,
                env : ::Process::Env = nil, clear_env : Bool = false,
                chdir : Path | String? = nil) : ProcessSupervision::Child
        {% if flag?(:linux) %}
          run_on_execution_context("process-supervision-posix-spawn") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir)
            group = @pgid.to_i32
            pending = @mutex.synchronize do
              check_open_locked
              ProcessSupervision::Linux::RawSpawn.create(prepared, pgroup: group)
            end
            ProcessSupervision::Linux::RawSpawn.complete(pending, prepared, self, group)
          end
        {% elsif flag?(:darwin) %}
          run_on_execution_context("process-supervision-posix-spawn") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir)
            @mutex.synchronize do
              check_open_locked
              _, process, handle = ProcessSupervision::POSIX::DarwinSpawn.launch(prepared, @pgid.to_i32)
              ProcessSupervision::Child.new(process, handle, self)
            end
          end
        {% else %}
          raise ProcessSupervision::Error::Unsupported.new("spawning is not implemented for this target yet")
        {% end %}
      end

      # Spawns a child that leads a new process group and returns it; `child.group` is that group (pgid == child pid).
      # Closing or shutting down the group is the caller's job, as for every Child.
      def self.spawn_leader(command : String, args : Enumerable(String) = [] of String, *,
                            env : ::Process::Env = nil, clear_env : Bool = false,
                            chdir : Path | String? = nil) : ProcessSupervision::Child
        {% if flag?(:linux) %}
          run_on_execution_context("process-supervision-posix-spawn-leader") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir)
            pending = ProcessSupervision::Linux::RawSpawn.create(prepared, pgroup: 0)
            # the group object needs the pid, so build it from the pending child
            ProcessSupervision::Linux::RawSpawn.complete(pending, prepared, new(pending.pid.to_i64), nil)
          end
        {% elsif flag?(:darwin) %}
          run_on_execution_context("process-supervision-posix-spawn-leader") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir)
            pid, process, handle = ProcessSupervision::POSIX::DarwinSpawn.launch(prepared, 0)
            ProcessSupervision::Child.new(process, handle, new(pid.to_i64))
          end
        {% else %}
          raise ProcessSupervision::Error::Unsupported.new("spawning is not implemented for this target yet")
        {% end %}
      end

      def mechanism : ProcessSupervision::Mechanism
        ProcessSupervision::Mechanism::ProcessGroup
      end

      def kill_on_close? : Bool
        false
      end

      def soft_termination? : Bool
        true
      end

      def empty? : Bool
        @mutex.synchronize do
          check_open_locked
          group_empty_locked?
        end
      end

      def wait_empty(timeout : Time::Span? = nil) : Bool
        run_on_execution_context("process-supervision-posix-wait-empty") do
          wait_empty_on_execution_context(timeout)
        end
      end

      def terminate : Nil
        signal(Signal::TERM)
      end

      def kill : Nil
        signal(Signal::KILL)
      end

      def close : Nil
        @mutex.synchronize do
          @closed = true
        end
      end

      def closed? : Bool
        @mutex.synchronize { @closed }
      end

      private def wait_empty_on_execution_context(timeout : Time::Span?) : Bool
        validate_timeout(timeout)
        deadline = timeout.try { |span| Time.instant + span }
        loop do
          return true if empty?
          if deadline
            remaining = deadline - Time.instant
            return false if remaining <= Time::Span.zero
            sleep({remaining, 10.milliseconds}.min)
          else
            sleep 10.milliseconds
          end
        end
      end

      private def signal(signal : Signal) : Nil
        @mutex.synchronize do
          check_open_locked
          rc = LibC.kill(-@pgid.to_i32, signal.value)
          return if rc == 0
          errno = Errno.value
          return if errno == Errno::ESRCH
          return if no_live_member?(errno)
          raise ProcessSupervision::Error::Native.new("killpg(#{signal})", errno.message, errno.value.to_i64)
        end
      end

      private def group_empty_locked? : Bool
        rc = LibC.kill(-@pgid.to_i32, 0)
        return false if rc == 0
        errno = Errno.value
        return true if errno == Errno::ESRCH
        return no_live_member?(errno) if errno == Errno::EPERM
        raise ProcessSupervision::Error::Native.new("killpg(0)", errno.message, errno.value.to_i64)
      end

      # Darwin returns EPERM, not ESRCH, from kill(-pgid, sig) once every process left in the group is a
      # zombie (exited, not yet reaped): nothing remains that can receive the signal. It does so for
      # signal 0, TERM and KILL alike, while Linux keeps delivering to zombies (rc 0) and reports ESRCH
      # only after reaping. Treating that EPERM as fatal made TERM -> grace -> KILL escalation raise
      # whenever the group died during the grace period. Measured natively (macOS 15 arm64):
      # explore/macos/signal_matrix.c, 100% EPERM for a KILL sent >= 1 ms after TERM.
      private def no_live_member?(errno : Errno) : Bool
        {% if flag?(:darwin) %}
          errno == Errno::EPERM
        {% else %}
          false
        {% end %}
      end

      private def check_open_locked : Nil
        raise ProcessSupervision::Error::Closed.new("process group controller is closed") if @closed
      end
    end
  end
{% end %}
