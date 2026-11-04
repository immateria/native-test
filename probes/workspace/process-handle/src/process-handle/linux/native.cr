{% if flag?(:linux) %}
  private lib LibProcessHandleLinux
    struct PollFd
      fd : Int32
      events : Int16
      revents : Int16
    end

    POLLIN  = 0x001_i16
    POLLERR = 0x008_i16
    POLLHUP = 0x010_i16

    fun poll(fds : PollFd*, nfds : LibC::ULong, timeout : Int32) : Int32
  end

  private module ProcessHandle::Linux::Native
    {% if flag?(:x86_64) || flag?(:aarch64) %}
      private SYS_PIDFD_SEND_SIGNAL = 424_i64
      private SYS_PIDFD_OPEN        = 434_i64
    {% end %}

    def self.retry_eintr(& : -> T) : T forall T
      loop do
        result = yield
        return result unless result == -1 && Errno.value == Errno::EINTR
      end
    end

    def self.open_pidfd(pid : Int64) : IO::FileDescriptor
      {% if flag?(:x86_64) || flag?(:aarch64) %}
        fd = retry_eintr { LibC.syscall(SYS_PIDFD_OPEN, pid.to_i32, 0_u32) }
        if fd < 0
          errno = Errno.value
          case errno
          when Errno::ESRCH
            raise ProcessHandle::Error::NoSuchProcess.new(pid)
          when Errno::EPERM, Errno::EACCES
            raise ProcessHandle::Error::AccessDenied.new(pid, errno.message)
          when Errno::ENOSYS, Errno::EINVAL
            raise ProcessHandle::Error::Unsupported.new("pidfd_open is unavailable on this Linux host")
          else
            raise ProcessHandle::Error::Native.new("pidfd_open", errno.message, errno.value.to_i64)
          end
        end
        IO::FileDescriptor.new(fd.to_i32)
      {% else %}
        raise ProcessHandle::Error::Unsupported.new("pidfd_open is not bound for this Linux architecture")
      {% end %}
    end

    # Each waiter owns its own fd reference. This prevents a concurrent close
    # of the parent ProcessHandle from recycling the fd used by an outstanding
    # event-loop registration. F_DUPFD_CLOEXEC is atomic with respect to exec.
    # Linux's F_DUPFD_CLOEXEC numeric command is 1030 on x86-64 and AArch64.
    private F_DUPFD_CLOEXEC = 1030

    def self.duplicate_pidfd(pidfd : IO::FileDescriptor) : IO::FileDescriptor
      duplicated = retry_eintr { LibC.fcntl(pidfd.fd, F_DUPFD_CLOEXEC, 0) }
      if duplicated < 0
        errno = Errno.value
        raise ProcessHandle::Error::Native.new("fcntl(F_DUPFD_CLOEXEC, pidfd)", errno.message, errno.value.to_i64)
      end
      begin
        IO::FileDescriptor.new(duplicated)
      rescue ex
        # A temporary descriptor has no owner if wrapping failed. Best-effort
        # cleanup must not replace the error that prevented construction.
        LibC.close(duplicated)
        raise ex
      end
    end

    def self.ready?(pidfd : IO::FileDescriptor) : Bool
      raise ProcessHandle::Error::Closed.new("process handle is closed") if pidfd.closed?
      pollfd = LibProcessHandleLinux::PollFd.new(
        fd: pidfd.fd,
        events: LibProcessHandleLinux::POLLIN,
        revents: 0_i16
      )
      rc = retry_eintr { LibProcessHandleLinux.poll(pointerof(pollfd), 1_u64, 0) }
      if rc < 0
        errno = Errno.value
        raise ProcessHandle::Error::Native.new("poll(pidfd)", errno.message, errno.value.to_i64)
      end
      return false if rc == 0
      pollfd.revents != 0
    end

    def self.io_error(operation : String, error : IO::Error) : ProcessHandle::Error::Native
      errno = error.os_error.as?(Errno)
      ProcessHandle::Error::Native.new(operation, error.message || "failed", errno.try(&.value.to_i64))
    end

    def self.send_signal(pidfd : IO::FileDescriptor, pid : Int64, signal : Signal) : Nil
      {% if flag?(:x86_64) || flag?(:aarch64) %}
        rc = retry_eintr do
          LibC.syscall(SYS_PIDFD_SEND_SIGNAL, pidfd.fd, signal.value, Pointer(Void).null, 0_u32).to_i32
        end
        return if rc == 0
        errno = Errno.value
        return if errno == Errno::ESRCH
        case errno
        when Errno::EPERM, Errno::EACCES
          raise ProcessHandle::Error::AccessDenied.new(pid, errno.message)
        when Errno::ENOSYS, Errno::EINVAL
          raise ProcessHandle::Error::Unsupported.new("pidfd_send_signal is unavailable on this Linux host")
        else
          raise ProcessHandle::Error::Native.new("pidfd_send_signal", errno.message, errno.value.to_i64)
        end
      {% else %}
        raise ProcessHandle::Error::Unsupported.new("pidfd_send_signal is not bound for this Linux architecture")
      {% end %}
    end

    # Point-in-time Linux process state, adapted from pty-server daemon
    # supervision. `/proc/<pid>/stat` gives both state and the start-time token.
    # If procfs cannot be inspected but kill(pid, 0) still proves presence, the
    # result is Unknown rather than optimistically Live or falsely Dead.
    def self.observe(pid : Int64) : ProcessHandle::Observation
      if stat = read_stat(pid)
        state, token = stat
        observed_state = case state
                         when "Z"
                           ProcessHandle::Observation::State::Zombie
                         when "X", "x"
                           ProcessHandle::Observation::State::Dead
                         when "R", "S", "D", "T", "t", "W", "K", "P", "I"
                           ProcessHandle::Observation::State::Live
                         else
                           # Do not turn an unknown kernel process-state code
                           # into liveness authority.
                           ProcessHandle::Observation::State::Unknown
                         end
        identity = ProcessHandle::Identity.new(pid, token)
        return ProcessHandle::Observation.new(pid, observed_state, identity)
      end

      ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Dead, nil)
    rescue ex : ProcessHandle::Error::AccessDenied
      state = process_present_by_signal?(pid) ? ProcessHandle::Observation::State::Unknown : ProcessHandle::Observation::State::Dead
      ProcessHandle::Observation.new(pid, state, nil)
    end

    # /proc/<pid>/stat field 22. The comm field is parenthesized and may contain
    # spaces or parentheses, so split only after its final ') '.
    def self.lookup_identity(pid : Int64) : ProcessHandle::Identity?
      stat = read_stat(pid)
      stat ? ProcessHandle::Identity.new(pid, stat[1]) : nil
    end

    private def self.read_stat(pid : Int64) : Tuple(String, UInt64)?
      data = File.read("/proc/#{pid}/stat")
      close_paren = data.rindex(')')
      raise ProcessHandle::Error::Native.new("read /proc/#{pid}/stat", "malformed stat record") unless close_paren

      rest_start = close_paren + 2
      raise ProcessHandle::Error::Native.new("read /proc/#{pid}/stat", "malformed stat record") if rest_start >= data.bytesize
      fields = data.byte_slice(rest_start, data.bytesize - rest_start).split
      # fields[0] is stat field 3 (state), so field 22 is offset 19.
      raise ProcessHandle::Error::Native.new("read /proc/#{pid}/stat", "missing start-time field") unless token = fields[19]?
      {fields[0]? || "", token.to_u64}
    rescue File::NotFoundError
      nil
    rescue ex : File::AccessDeniedError
      raise ProcessHandle::Error::AccessDenied.new(pid, ex.message || "access denied")
    rescue ex : File::Error
      errno = ex.os_error.as?(Errno)
      return nil if errno.in?(Errno::ENOENT, Errno::ESRCH)
      if errno.in?(Errno::EACCES, Errno::EPERM)
        raise ProcessHandle::Error::AccessDenied.new(pid, ex.message || "access denied")
      end
      raise ProcessHandle::Error::Native.new(
        "read /proc/#{pid}/stat", ex.message || "failed", errno.try(&.value.to_i64)
      )
    rescue ex : ProcessHandle::Error
      raise ex
    rescue ex
      raise ProcessHandle::Error::Native.new("read /proc/#{pid}/stat", ex.message || ex.class.name)
    end

    private def self.process_present_by_signal?(pid : Int64) : Bool
      return false unless pid > 0 && pid <= Int32::MAX
      rc = LibC.kill(pid.to_i32, 0)
      return true if rc == 0
      Errno.value == Errno::EPERM
    rescue
      false
    end
  end
{% end %}
