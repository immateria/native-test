{% if flag?(:linux) %}
  class ProcessHandle::Linux
    def self.observe(pid : Int64) : ProcessHandle::Observation
      Native.observe(pid)
    end

    def self.lookup_identity(pid : Int64) : ProcessHandle::Identity?
      Native.lookup_identity(pid)
    end

    @pidfd : IO::FileDescriptor?
    @mutex = Thread::Mutex.new

    def self.open(pid : Int64) : self
      raise ArgumentError.new("pid must be positive") unless pid > 0

      # The pidfd pins process identity. Read the persistent token while that
      # process is still known alive; if it exits during attachment, retrying
      # is safer than pairing the pidfd with a recycled PID's /proc record.
      3.times do
        pidfd = Native.open_pidfd(pid)
        begin
          identity = begin
            Native.lookup_identity(pid)
          rescue ProcessHandle::Error::AccessDenied
            # A pidfd is itself the stable kernel reference. Restricted procfs
            # must not throw that capability away merely because a detached
            # generation token cannot also be recorded.
            nil
          end

          if Native.ready?(pidfd)
            pidfd.close
            next
          end

          return new(identity || ProcessHandle::Identity.new(pid, nil), pidfd)
        rescue ex
          # Preserve the authoritative open/identity failure. This temporary
          # pidfd has not escaped and cleanup must not replace the primary
          # diagnosis, matching PTY spawn rollback precedence.
          pidfd.close rescue nil
          raise ex
        end
      end

      raise ProcessHandle::Error::NoSuchProcess.new(pid)
    end

    # Adopts a direct child that the caller has just created. Unlike `open`, a child that has already exited is
    # accepted: a pidfd names its process until the process is reaped, zombie included, so a command that finishes at
    # once can still be supervised (`alive?` is false and `wait` returns immediately). `pidfd` is taken over when given
    # (clone3 with CLONE_PIDFD returns one atomically with the creation); otherwise one is opened here, which can only
    # fail if the child was already reaped.
    def self.adopt_child(pid : Int64, pidfd : Int32? = nil) : self
      raise ArgumentError.new("pid must be positive") unless pid > 0

      descriptor = pidfd ? IO::FileDescriptor.new(pidfd) : Native.open_pidfd(pid)
      begin
        identity = begin
          Native.lookup_identity(pid)
        rescue ProcessHandle::Error::AccessDenied
          nil
        end
        new(identity || ProcessHandle::Identity.new(pid, nil), descriptor)
      rescue ex
        descriptor.close rescue nil
        raise ex
      end
    end

    private def initialize(identity : ProcessHandle::Identity, @pidfd : IO::FileDescriptor)
      super(identity)
    end

    def mechanism : ProcessHandle::Mechanism
      ProcessHandle::Mechanism::Pidfd
    end

    def alive? : Bool
      @mutex.synchronize do
        pidfd = checked_pidfd
        !Native.ready?(pidfd)
      end
    end

    def wait(timeout : Time::Span? = nil) : Bool
      run_on_execution_context("process-handle-linux-wait") do
        wait_on_execution_context(timeout)
      end
    end

    private def wait_on_execution_context(timeout : Time::Span?) : Bool
      validate_timeout(timeout)
      deadline = timeout.try { |span| Time.instant + span }
      # Duplicate under the ownership lock, then wait without holding it.
      # Closing this ProcessHandle cannot recycle a descriptor still watched
      # by another fiber, and the wait itself does not block close or signals.
      observed = @mutex.synchronize { Native.duplicate_pidfd(checked_pidfd) }
      begin
        loop do
          return true if Native.ready?(observed)
          if deadline
            remaining = deadline - Time.instant
            return false if remaining <= Time::Span.zero
            observed.read_timeout = remaining
          end
          begin
            # The runtime event loop waits for pidfd readiness without scheduling
            # periodic process-state polls. Backend support is verified per lane.
            Crystal::EventLoop.current.wait_readable(observed)
          rescue IO::TimeoutError
            return false
          rescue ex : IO::Error
            raise Native.io_error("wait(pidfd)", ex)
          end
        end
      ensure
        # This fd exists only for readiness observation. Keep the result/error
        # authoritative if a temporary-fd close reports a secondary failure.
        observed.close rescue nil
      end
    end

    def terminate : Nil
      signal(Signal::TERM)
    end

    def kill : Nil
      signal(Signal::KILL)
    end

    def close : Nil
      run_on_execution_context("process-handle-linux-close") do
        @mutex.synchronize do
          if pidfd = @pidfd
            # IO::FileDescriptor relinquishes ownership before surfacing a native
            # close error. Publish logical closure first and never retry the raw fd
            # number, which may already be reusable.
            @pidfd = nil
            begin
              pidfd.close unless pidfd.closed?
            rescue ex : IO::Error
              raise Native.io_error("close(pidfd)", ex)
            end
          end
        end
      end
    end

    def closed? : Bool
      @mutex.synchronize { @pidfd.nil? }
    end

    def native_fd : Int32
      @mutex.synchronize { checked_pidfd.fd }
    end

    private def signal(signal : Signal) : Nil
      @mutex.synchronize do
        pidfd = checked_pidfd
        return if Native.ready?(pidfd)
        Native.send_signal(pidfd, pid, signal)
      end
    end

    private def checked_pidfd : IO::FileDescriptor
      pidfd = @pidfd
      raise ProcessHandle::Error::Closed.new("process handle is closed") unless pidfd
      pidfd
    end
  end
{% end %}
