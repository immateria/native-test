{% if flag?(:unix) %}
  module ProcessSupervision::POSIX
    # Controller for an existing POSIX process group. A process group is not a
    # kernel lifetime container: descendants can call setsid/setpgid and escape,
    # and closing this object cannot kill the group after an abrupt owner death.
    #
    # Children spawned through this controller (by default) carry an environment
    # marker unique to it, `PROCESS_SUPERVISION_GROUP=<token>`. A descendant that
    # left the group but kept that environment is still found (`#escapees`):
    # `terminate`, `kill` and `shutdown` signal it too, and `empty?` stays false
    # while it lives. A descendant that clears or rewrites its environment
    # before it execs is not found.
    class ProcessGroup < ProcessSupervision::Group
      getter pgid : Int64

      @mutex = Thread::Mutex.new
      @closed = false
      @marker : String?

      # *marker* is the descendant-marker token of a group this process spawned into (see `#escapees`), if any.
      def initialize(@pgid : Int64, marker : String? = nil)
        @marker = marker
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
      # group is not a kill-on-close container: a descendant can still leave it (setsid/setpgid); with
      # *track_descendants* (the default) it carries this controller's environment marker, so `#escapees` finds it.
      def spawn(command : String, args : Enumerable(String) = [] of String, *,
                env : ::Process::Env = nil, clear_env : Bool = false,
                chdir : Path | String? = nil,
                input : ::Process::Stdio = ::Process::Redirect::Inherit,
                output : ::Process::Stdio = ::Process::Redirect::Inherit,
                error : ::Process::Stdio = ::Process::Redirect::Inherit,
                track_descendants : Bool = true) : ProcessSupervision::Child
        marker = track_descendants ? MarkerScan.entry(@mutex.synchronize { @marker ||= MarkerScan.new_token }) : nil
        {% if flag?(:linux) %}
          run_on_execution_context("process-supervision-posix-spawn") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir, marker)
            plumbing = ProcessSupervision::POSIX::Spawn::Plumbing.build(input, output, error)
            group = @pgid.to_i32
            pending = begin
              @mutex.synchronize do
                check_open_locked
                ProcessSupervision::Linux::RawSpawn.create(prepared, plumbing, pgroup: group)
              end
            rescue ex
              plumbing.abandon
              raise ex
            end
            ProcessSupervision::Linux::RawSpawn.complete(pending, prepared, plumbing, self, group)
          end
        {% elsif flag?(:darwin) %}
          run_on_execution_context("process-supervision-posix-spawn") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir, marker)
            plumbing = ProcessSupervision::POSIX::Spawn::Plumbing.build(input, output, error)
            begin
              @mutex.synchronize do
                check_open_locked
                _, process, handle = ProcessSupervision::POSIX::DarwinSpawn.launch(prepared, @pgid.to_i32, plumbing)
                ProcessSupervision::Child.new(process, handle, self, plumbing.input, plumbing.output, plumbing.error, plumbing.copies)
              end
            rescue ex
              plumbing.abandon
              raise ex
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
                            chdir : Path | String? = nil,
                            input : ::Process::Stdio = ::Process::Redirect::Inherit,
                            output : ::Process::Stdio = ::Process::Redirect::Inherit,
                            error : ::Process::Stdio = ::Process::Redirect::Inherit,
                            track_descendants : Bool = true) : ProcessSupervision::Child
        token = track_descendants ? MarkerScan.new_token : nil
        marker = token.try { |value| MarkerScan.entry(value) }
        {% if flag?(:linux) %}
          run_on_execution_context("process-supervision-posix-spawn-leader") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir, marker)
            plumbing = ProcessSupervision::POSIX::Spawn::Plumbing.build(input, output, error)
            pending = ProcessSupervision::Linux::RawSpawn.create(prepared, plumbing, pgroup: 0)
            # the group object needs the pid, so build it from the pending child
            ProcessSupervision::Linux::RawSpawn.complete(pending, prepared, plumbing, new(pending.pid.to_i64, token), nil)
          end
        {% elsif flag?(:darwin) %}
          run_on_execution_context("process-supervision-posix-spawn-leader") do
            prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir, marker)
            plumbing = ProcessSupervision::POSIX::Spawn::Plumbing.build(input, output, error)
            pid, process, handle = ProcessSupervision::POSIX::DarwinSpawn.launch(prepared, 0, plumbing)
            ProcessSupervision::Child.new(process, handle, new(pid.to_i64, token), plumbing.input, plumbing.output, plumbing.error, plumbing.copies)
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

      # Whether the group has no live member and no marked descendant lives outside it (see `#escapees`).
      def empty? : Bool
        token = @mutex.synchronize do
          check_open_locked
          return false unless group_empty_locked?
          @marker
        end
        token.nil? || escapees_for(token).empty?
      end

      # Whether children spawned through this controller carry its descendant marker.
      def tracks_descendants? : Bool
        @mutex.synchronize { !@marker.nil? }
      end

      # Live processes outside the process group that carry this controller's environment marker: descendants that
      # called setsid or setpgid, or were reparented after a double fork. Empty when nothing was spawned with tracking.
      def escapees : Array(Int64)
        token = @mutex.synchronize do
          check_open_locked
          @marker
        end
        token ? escapees_for(token) : [] of Int64
      end

      private def escapees_for(token : String) : Array(Int64)
        MarkerScan.scan(token).reject { |pid| LibC.getpgid(pid.to_i32) == @pgid.to_i32 }
      end

      # Signals one marked process through a handle that watches it first, then checks the marker again: whatever holds
      # the PID at that point is either the marked process (its exit would now be seen, so a recycled PID is never
      # signalled) or not marked and left alone. A process this user may not signal is left too; `empty?` stays false.
      private def signal_escapee(pid : Int64, entry : String, signal : Signal) : Nil
        handle = begin
          {% if flag?(:darwin) %}
            ProcessHandle::Kqueue.watch(pid)
          {% else %}
            ProcessHandle.open(pid)
          {% end %}
        rescue ProcessHandle::Error
          return
        end
        begin
          return unless MarkerScan.marked?(pid, entry) && handle.alive?
          signal == Signal::KILL ? handle.kill : handle.terminate
        rescue ProcessHandle::Error
        ensure
          handle.close rescue nil
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
        token = @mutex.synchronize do
          check_open_locked
          rc = LibC.kill(-@pgid.to_i32, signal.value)
          unless rc == 0
            errno = Errno.value
            unless errno == Errno::ESRCH || no_live_member?(errno)
              raise ProcessSupervision::Error::Native.new("killpg(#{signal})", errno.message, errno.value.to_i64)
            end
          end
          @marker
        end
        return unless token
        entry = MarkerScan.entry(token)
        escapees_for(token).each { |pid| signal_escapee(pid, entry, signal) }
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
