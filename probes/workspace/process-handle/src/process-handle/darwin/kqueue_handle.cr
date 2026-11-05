{% if flag?(:darwin) %}
  require "c/sys/event"
  require "c/fcntl"

  # A handle for a direct child that the caller just created on macOS, where no stable process reference exists.
  #
  # An exit watch (kqueue EVFILT_PROC / NOTE_EXIT) is registered right after the child is created. It is only reliable
  # when the child could not yet have exited, which is why the supervision layer starts macOS children suspended
  # (POSIX_SPAWN_START_SUSPENDED) and resumes them after the watch exists: registering on an already exited process
  # fails with ESRCH (measured natively), and that case is reported as "already exited", which for a child we created is
  # the truth.
  #
  # This is weaker than a Linux pidfd or a Windows HANDLE and is not exposed through `ProcessHandle.open`: the kernel
  # does not retain the process, so `kill` is only as safe as the exit watch is current. It never signals a process whose
  # exit has been observed, which closes the window in which the PID could have been recycled.
  class ProcessHandle::Kqueue < ProcessHandle
    private EVFILT_PROC =         -5_i16
    private EV_RECEIPT  =     0x0040_u16
    private NOTE_EXIT   = 0x80000000_u32

    @mutex = Thread::Mutex.new
    @kq : Int32
    @exited : Bool
    @closed = false

    def self.adopt_child(pid : Int64) : self
      watch(pid)
    end

    # The same exit watch on a process that is not the caller's child (one found by a scan). The watch is registered
    # first, so the caller can then confirm that the PID still names the process it found (its `identity.generation`, the
    # start time, against the scan's) and know that a later exit is seen. A process that already exited reads as
    # exited, and this handle never signals it.
    def self.watch(pid : Int64) : self
      raise ArgumentError.new("pid must be positive") unless pid > 0
      raise ArgumentError.new("pid exceeds native pid range") if pid > Int32::MAX

      kq = LibC.kqueue
      if kq < 0
        errno = Errno.value
        raise ProcessHandle::Error::Native.new("kqueue", errno.message, errno.value.to_i64)
      end
      LibC.fcntl(kq, LibC::F_SETFD, LibC::FD_CLOEXEC)

      begin
        change = LibC::Kevent.new
        change.ident = pid.to_u64
        change.filter = EVFILT_PROC
        change.flags = LibC::EV_ADD | LibC::EV_CLEAR | EV_RECEIPT
        change.fflags = NOTE_EXIT
        receipt = LibC::Kevent.new
        zero = LibC::Timespec.new
        zero.tv_sec = 0
        zero.tv_nsec = 0
        count = LibC.kevent(kq, pointerof(change), 1, pointerof(receipt), 1, pointerof(zero))
        exited = false
        if count < 0
          errno = Errno.value
          raise ProcessHandle::Error::Native.new("kevent(register)", errno.message, errno.value.to_i64)
        elsif count > 0 && (receipt.flags & LibC::EV_ERROR) != 0 && receipt.data != 0
          if receipt.data == Errno::ESRCH.value
            exited = true
          else
            raise ProcessHandle::Error::Native.new("kevent(register)", "exit watch failed", receipt.data.to_i64)
          end
        end

        identity = begin
          ProcessHandle::Darwin.lookup_identity(pid)
        rescue ProcessHandle::Error::AccessDenied
          nil
        end
        new(identity || ProcessHandle::Identity.new(pid, nil), kq, exited)
      rescue ex
        LibC.close(kq)
        raise ex
      end
    end

    private def initialize(identity : ProcessHandle::Identity, @kq : Int32, @exited : Bool)
      super(identity)
    end

    def mechanism : ProcessHandle::Mechanism
      ProcessHandle::Mechanism::Kqueue
    end

    def alive? : Bool
      @mutex.synchronize do
        check_open_locked
        !exited_locked?
      end
    end

    # Polls the exit watch every few milliseconds, yielding to other fibers between polls.
    def wait(timeout : Time::Span? = nil) : Bool
      run_on_execution_context("process-handle-kqueue-wait") do
        wait_on_execution_context(timeout)
      end
    end

    # Event-driven: a kqueue descriptor is itself readable while it has a pending event, so a copy of it is handed to the
    # runtime's event loop (which is kqueue on macOS) and the fiber sleeps until the exit is reported. If the event loop
    # refuses the descriptor, falls back to polling every 5 ms.
    private def wait_on_execution_context(timeout : Time::Span?) : Bool
      validate_timeout(timeout)
      deadline = timeout.try { |span| Time.instant + span }
      watcher = @mutex.synchronize do
        check_open_locked
        LibC.fcntl(@kq, 67, 0) # F_DUPFD_CLOEXEC
      end
      return poll_wait(deadline) if watcher < 0
      IO::FileDescriptor.set_blocking(watcher, false)
      io = IO::FileDescriptor.new(watcher)
      begin
        loop do
          return true unless alive?
          remaining = deadline.try { |limit| limit - Time.instant }
          return false if remaining && remaining <= Time::Span.zero
          io.read_timeout = remaining
          begin
            Crystal::EventLoop.current.wait_readable(io)
          rescue IO::TimeoutError
            return !alive?
          rescue IO::Error
            return poll_wait(deadline)
          end
        end
      ensure
        io.close rescue nil
      end
    end

    private def poll_wait(deadline : Time::Instant?) : Bool
      loop do
        return true unless alive?
        if deadline
          remaining = deadline - Time.instant
          return false if remaining <= Time::Span.zero
          sleep({remaining, 5.milliseconds}.min)
        else
          sleep 5.milliseconds
        end
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
        return if @closed
        @closed = true
        LibC.close(@kq)
      end
    end

    def closed? : Bool
      @mutex.synchronize { @closed }
    end

    # Sends *signal* to this process; never once its exit has been observed (so never to a recycled PID).
    def signal(signal : Signal) : Nil
      @mutex.synchronize do
        check_open_locked
        return if exited_locked?
        return if LibC.kill(pid.to_i32, signal.value) == 0
        errno = Errno.value
        return if errno == Errno::ESRCH
        if errno == Errno::EPERM || errno == Errno::EACCES
          raise ProcessHandle::Error::AccessDenied.new(pid, errno.message)
        end
        raise ProcessHandle::Error::Native.new("kill", errno.message, errno.value.to_i64)
      end
    end

    private def exited_locked? : Bool
      return true if @exited
      event = LibC::Kevent.new
      zero = LibC::Timespec.new
      zero.tv_sec = 0
      zero.tv_nsec = 0
      loop do
        count = LibC.kevent(@kq, Pointer(LibC::Kevent).null, 0, pointerof(event), 1, pointerof(zero))
        if count < 0
          errno = Errno.value
          next if errno == Errno::EINTR
          raise ProcessHandle::Error::Native.new("kevent(poll)", errno.message, errno.value.to_i64)
        end
        if count > 0 && event.filter == EVFILT_PROC && (event.fflags & NOTE_EXIT) != 0
          @exited = true
        end
        break
      end
      @exited
    end

    private def check_open_locked : Nil
      raise ProcessHandle::Error::Closed.new("process handle is closed") if @closed
    end
  end
{% end %}
