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
  # Every handle's watch lives in one shared kqueue (`ProcessHandle::Darwin::ExitWatcher`), so a handle costs no
  # descriptor, and `wait` is event-driven: a dedicated thread is woken by the kernel when an exit arrives and wakes the
  # waiting fiber through a pipe the runtime's event loop can wait on.
  #
  # This is weaker than a Linux pidfd or a Windows HANDLE and is not exposed through `ProcessHandle.open`: the kernel
  # does not retain the process, so `kill` is only as safe as the exit watch is current. It never signals a process whose
  # exit has been observed, which closes the window in which the PID could have been recycled.
  # One kqueue holding the exit watch (EVFILT_PROC / NOTE_EXIT) of every `ProcessHandle::Kqueue`, and one thread that
  # sleeps until it has events.
  #
  # Crystal's event loop cannot wait on a kqueue descriptor (it also registers EVFILT_WRITE, which the kernel refuses
  # for a kqueue), so a dedicated thread (an isolated execution context) blocks in kevent instead. It does not consume
  # the exit events itself: it waits on a second kqueue in which the shared one is registered for EVFILT_READ, and only
  # drains the shared kqueue under the mutex. Every reader of the watch state (`exited?`, `add_waiter`, `watch`) drains
  # it under the same mutex first, so an exit the kernel has posted is never invisible to a caller merely because the
  # thread has dequeued it and not yet recorded it.
  #
  # A waiting fiber gets a pipe; the thread writes one byte to it when the process exits (a byte, not end-of-file: a
  # copy of the write end leaked into a concurrently spawned child would keep end-of-file from ever arriving).
  #
  # kqueue identifies a watch by (pid, filter), so all handles of one pid share one `Entry`. An entry leaves the table
  # when its exit is recorded or its last handle closes; a recycled pid therefore always gets a fresh registration
  # (a pid is recycled only after its process was reaped, by which time its exit has been posted and is drained by the
  # next `watch`).
  #
  # Not fork-safe: a forked child has neither the kqueue (kqueues are not inherited) nor the thread.
  class ProcessHandle::Darwin::ExitWatcher
    private EVFILT_PROC =         -5_i16
    private EVFILT_READ =         -1_i16
    private EV_RECEIPT  =     0x0040_u16
    private EV_ONESHOT  =     0x0010_u16
    private NOTE_EXIT   = 0x80000000_u32

    # :nodoc:
    class Entry
      getter pid : Int32
      property exited = false
      property handles = 0
      getter waiters = [] of Int32

      def initialize(@pid : Int32)
      end
    end

    @@instance : self? = nil
    @@instance_mutex = Thread::Mutex.new

    def self.instance : self
      @@instance_mutex.synchronize { @@instance ||= new }
    end

    @mutex = Thread::Mutex.new
    @entries = {} of Int32 => Entry
    @kq : Int32
    @outer : Int32
    @thread_started = false

    private def initialize
      @kq = ExitWatcher.new_kqueue
      @outer = ExitWatcher.new_kqueue
      change = LibC::Kevent.new
      change.ident = @kq.to_u64
      change.filter = EVFILT_READ
      change.flags = LibC::EV_ADD
      if LibC.kevent(@outer, pointerof(change), 1, Pointer(LibC::Kevent).null, 0, Pointer(LibC::Timespec).null) < 0
        errno = Errno.value
        raise ProcessHandle::Error::Native.new("kevent(watch kqueue)", errno.message, errno.value.to_i64)
      end
    end

    protected def self.new_kqueue : Int32
      kq = LibC.kqueue
      if kq < 0
        errno = Errno.value
        raise ProcessHandle::Error::Native.new("kqueue", errno.message, errno.value.to_i64)
      end
      LibC.fcntl(kq, LibC::F_SETFD, LibC::FD_CLOEXEC)
      kq
    end

    # Registers an exit watch for *pid*, or joins the existing one. Returns nil when the process has already exited
    # (the kernel answers ESRCH).
    def watch(pid : Int32) : Entry?
      @mutex.synchronize do
        drain_locked
        if entry = @entries[pid]?
          entry.handles += 1
          return entry
        end
        change = LibC::Kevent.new
        change.ident = pid.to_u64
        change.filter = EVFILT_PROC
        change.flags = LibC::EV_ADD | EV_ONESHOT | EV_RECEIPT
        change.fflags = NOTE_EXIT
        receipt = LibC::Kevent.new
        zero = LibC::Timespec.new
        count = LibC.kevent(@kq, pointerof(change), 1, pointerof(receipt), 1, pointerof(zero))
        if count < 0
          errno = Errno.value
          raise ProcessHandle::Error::Native.new("kevent(register)", errno.message, errno.value.to_i64)
        elsif count > 0 && (receipt.flags & LibC::EV_ERROR) != 0 && receipt.data != 0
          return nil if receipt.data == Errno::ESRCH.value
          raise ProcessHandle::Error::Native.new("kevent(register)", "exit watch failed", receipt.data.to_i64)
        end
        entry = Entry.new(pid)
        entry.handles = 1
        @entries[pid] = entry
        start_thread_locked
        entry
      end
    end

    def exited?(entry : Entry) : Bool
      @mutex.synchronize do
        drain_locked unless entry.exited
        entry.exited
      end
    end

    # A pipe whose read end becomes readable when *entry*'s process exits, or nil if it already has.
    # Returns {read end, write end}; pass the write end to `remove_waiter` when giving up.
    def add_waiter(entry : Entry) : {Int32, Int32}?
      @mutex.synchronize do
        drain_locked
        return nil if entry.exited
        fds = uninitialized Int32[2]
        if LibC.pipe(fds) != 0
          errno = Errno.value
          raise ProcessHandle::Error::Native.new("pipe", errno.message, errno.value.to_i64)
        end
        fds.each { |fd| LibC.fcntl(fd, LibC::F_SETFD, LibC::FD_CLOEXEC) }
        entry.waiters << fds[1]
        {fds[0], fds[1]}
      end
    end

    def remove_waiter(entry : Entry, write_end : Int32) : Nil
      @mutex.synchronize do
        LibC.close(write_end) if entry.waiters.delete(write_end)
      end
    end

    def release(entry : Entry) : Nil
      @mutex.synchronize do
        entry.handles -= 1
        return if entry.handles > 0 || entry.exited
        @entries.delete(entry.pid) if @entries[entry.pid]?.same?(entry)
        change = LibC::Kevent.new
        change.ident = entry.pid.to_u64
        change.filter = EVFILT_PROC
        change.flags = LibC::EV_DELETE | EV_RECEIPT
        receipt = LibC::Kevent.new
        zero = LibC::Timespec.new
        LibC.kevent(@kq, pointerof(change), 1, pointerof(receipt), 1, pointerof(zero))
        entry.waiters.each { |fd| LibC.close(fd) }
        entry.waiters.clear
      end
    end

    # Records every exit the kernel has posted. Caller holds @mutex.
    private def drain_locked : Nil
      events = uninitialized LibC::Kevent[16]
      zero = LibC::Timespec.new
      loop do
        count = LibC.kevent(@kq, Pointer(LibC::Kevent).null, 0, events.to_unsafe, 16, pointerof(zero))
        if count < 0
          errno = Errno.value
          next if errno == Errno::EINTR
          raise ProcessHandle::Error::Native.new("kevent(drain)", errno.message, errno.value.to_i64)
        end
        count.times do |i|
          event = events[i]
          next unless event.filter == EVFILT_PROC && (event.fflags & NOTE_EXIT) != 0
          pid = event.ident.to_i32
          next unless entry = @entries.delete(pid)
          entry.exited = true
          byte = 1_u8
          entry.waiters.each do |fd|
            LibC.write(fd, pointerof(byte), 1)
            LibC.close(fd)
          end
          entry.waiters.clear
        end
        break if count < 16
      end
    end

    private def start_thread_locked : Nil
      return if @thread_started
      @thread_started = true
      Fiber::ExecutionContext::Isolated.new("process-handle-exit-watcher") { run }
    end

    private def run : Nil
      event = LibC::Kevent.new
      loop do
        count = LibC.kevent(@outer, Pointer(LibC::Kevent).null, 0, pointerof(event), 1, Pointer(LibC::Timespec).null)
        next if count <= 0
        begin
          @mutex.synchronize { drain_locked }
        rescue
          sleep 10.milliseconds # a failing drain must not end the thread; callers drain (and raise) themselves
        end
      end
    end
  end

  class ProcessHandle::Kqueue < ProcessHandle
    @mutex = Thread::Mutex.new
    # nil when the process had already exited when the watch was registered
    @entry : ProcessHandle::Darwin::ExitWatcher::Entry?
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

      watcher = ProcessHandle::Darwin::ExitWatcher.instance
      entry = watcher.watch(pid.to_i32)
      begin
        identity = begin
          ProcessHandle::Darwin.lookup_identity(pid)
        rescue ProcessHandle::Error::AccessDenied
          nil
        end
        new(identity || ProcessHandle::Identity.new(pid, nil), entry)
      rescue ex
        entry.try { |live| watcher.release(live) }
        raise ex
      end
    end

    private def initialize(identity : ProcessHandle::Identity, @entry : ProcessHandle::Darwin::ExitWatcher::Entry?)
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

    # Waits for the exit event: the watcher thread wakes this fiber through a pipe, so nothing polls.
    def wait(timeout : Time::Span? = nil) : Bool
      run_on_execution_context("process-handle-kqueue-wait") do
        wait_on_execution_context(timeout)
      end
    end

    private def wait_on_execution_context(timeout : Time::Span?) : Bool
      validate_timeout(timeout)
      entry = @mutex.synchronize do
        check_open_locked
        @entry
      end
      return true unless entry
      watcher = ProcessHandle::Darwin::ExitWatcher.instance
      return true unless pipe = watcher.add_waiter(entry)
      read_end, write_end = pipe
      reader = IO::FileDescriptor.new(read_end) # a pipe: non-blocking, waited on by the event loop
      begin
        reader.read_timeout = timeout if timeout
        reader.read_byte
        true
      rescue IO::TimeoutError
        watcher.remove_waiter(entry, write_end)
        watcher.exited?(entry)
      ensure
        reader.close
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
        @entry.try { |entry| ProcessHandle::Darwin::ExitWatcher.instance.release(entry) }
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
      entry = @entry
      return true unless entry
      ProcessHandle::Darwin::ExitWatcher.instance.exited?(entry)
    end

    private def check_open_locked : Nil
      raise ProcessHandle::Error::Closed.new("process handle is closed") if @closed
    end
  end
{% end %}
