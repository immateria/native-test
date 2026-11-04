{% if flag?(:linux) %}
  private lib LibProcessSupervisionLinux
    fun setpgid(pid : Int32, pgid : Int32) : Int32
  end

  module ProcessSupervision::Linux
    # :nodoc:
    #
    # Creates a child with clone3 (CLONE_PIDFD, plus CLONE_INTO_CGROUP when a cgroup is given) or, where the kernel or a
    # seccomp filter refuses clone3 (a default Docker profile answers ENOSYS), with fork. Either way the child itself
    # finishes the setup with plain system calls before it execs: it enters the cgroup (fork path), joins or creates its
    # process group, resets every signal disposition and the signal mask, changes directory and execs. It never runs the
    # Crystal runtime and allocates nothing.
    #
    # Why not attach after spawn, or posix_spawn: measured natively, writing the pid to cgroup.procs after the child
    # exists lost children in 36-73% of trials under CPU contention, and posix_spawn cannot enter a cgroup. The pidfd is
    # obtained together with the process, so a child that exits at once can still be supervised.
    module RawSpawn
      private SYS_CLONE3           = 435_i64
      private CLONE_PIDFD          = 0x1000_u64
      private CLONE_INTO_CGROUP   = 0x200000000_u64
      private CLONE_ARGS_SIZE_VER2 =         88_u64
      private SIGCHLD_NUMBER       =         17_u64

      @@clone3_refused = false
      @@clone3_disabled = false

      # Test hook: forces the fork path.
      def self.clone3_disabled=(value : Bool)
        @@clone3_disabled = value
      end

      def self.clone3_disabled? : Bool
        @@clone3_disabled
      end

      def self.use_clone3? : Bool
        {% if flag?(:x86_64) || flag?(:aarch64) %}
          !@@clone3_refused && !@@clone3_disabled
        {% else %}
          false
        {% end %}
      end

      struct Pending
        getter pid : Int32
        getter pidfd : Int32?
        getter error_reader : IO::FileDescriptor

        def initialize(@pid : Int32, @pidfd : Int32?, @error_reader : IO::FileDescriptor)
        end
      end

      # Creates the process. Makes no call that can yield to another fiber, so it may run under a Thread::Mutex.
      def self.create(prepared : ProcessSupervision::POSIX::Spawn::Prepared, *, cgroup : Path? = nil, pgroup : Int32? = nil) : Pending
        error_reader, error_writer = IO.pipe
        cgroup_fd = -1
        procs_fd = -1
        begin
          if cgroup
            cgroup_fd = open_fd(cgroup.to_s, LibC::O_RDONLY | LibC::O_CLOEXEC)
            procs_fd = open_fd((cgroup / "cgroup.procs").to_s, LibC::O_WRONLY | LibC::O_CLOEXEC)
          end
          pid, pidfd = clone_process(prepared, cgroup_fd, procs_fd, pgroup, error_writer.fd)
          Pending.new(pid, pidfd >= 0 ? pidfd : nil, error_reader)
        rescue ex
          error_reader.close rescue nil
          raise ex
        ensure
          error_writer.close rescue nil
          LibC.close(cgroup_fd) if cgroup_fd >= 0
          LibC.close(procs_fd) if procs_fd >= 0
        end
      end

      # Waits for the exec to succeed or fail, adopts the process into Crystal's reaper and builds the Child. A failed
      # exec reaps the child and raises the stdlib's exception class for the errno.
      def self.complete(pending : Pending, prepared : ProcessSupervision::POSIX::Spawn::Prepared, group : ProcessSupervision::Group,
                        pgroup : Int32? = nil) : ProcessSupervision::Child
        process = ProcessSupervision::POSIX::Spawn.adopt(pending.pid)
        pidfd = pending.pidfd
        buffer = Bytes.new(4)
        failure = begin
          pending.error_reader.read_fully?(buffer)
        ensure
          pending.error_reader.close rescue nil
        end

        if failure
          errno = Errno.new(buffer.to_unsafe.as(Int32*).value)
          process.wait rescue nil
          LibC.close(pidfd) if pidfd
          if pgroup && pgroup > 0 && (errno == Errno::EPERM || errno == Errno::ESRCH)
            raise ProcessSupervision::Error::Unavailable.new("process group #{pgroup} cannot be joined: #{errno.message}")
          end
          raise ProcessSupervision::POSIX::Spawn.exec_error(prepared.command, errno)
        end

        begin
          handle = ProcessHandle::Linux.adopt_child(pending.pid.to_i64, pidfd)
          ProcessSupervision::Child.new(process, handle, group)
        rescue ex
          process.terminate(graceful: false) rescue nil
          process.wait rescue nil
          raise ex
        end
      end

      private def self.open_fd(path : String, flags : Int32) : Int32
        fd = LibC.open(path, flags)
        return fd if fd >= 0
        errno = Errno.value
        if errno == Errno::EACCES || errno == Errno::EPERM || errno == Errno::EROFS || errno == Errno::ENOENT
          raise ProcessSupervision::Error::Unavailable.new("cannot open #{path}: #{errno.message}")
        end
        raise ProcessSupervision::Error::Native.new("open(#{path})", errno.message, errno.value.to_i64)
      end

      private def self.clone_process(prepared : ProcessSupervision::POSIX::Spawn::Prepared, cgroup_fd : Int32, procs_fd : Int32,
                                     pgroup : Int32?, error_fd : Int32) : {Int32, Int32}
        mask = uninitialized LibC::SigsetT
        previous = uninitialized LibC::SigsetT
        # Block every signal around the fork so the child cannot run one of the runtime's handlers (they write to the
        # parent's signal pipe) before it execs; the stop-the-world signals stay open, as in the stdlib.
        LibC.sigfillset(pointerof(mask))
        LibC.sigdelset(pointerof(mask), Crystal::System::Thread.sig_suspend)
        LibC.sigdelset(pointerof(mask), Crystal::System::Thread.sig_resume)
        if LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(mask), pointerof(previous)) != 0
          raise ProcessSupervision::Error::Native.new("pthread_sigmask", "failed to block signals")
        end

        pid = -1
        pidfd = -1_i32
        failure = Errno::NONE
        begin
          Crystal::System::Process.lock_write do
            if use_clone3?
              args = StaticArray(UInt64, 11).new(0_u64)
              args[0] = CLONE_PIDFD | (cgroup_fd >= 0 ? CLONE_INTO_CGROUP : 0_u64)
              args[1] = pointerof(pidfd).address
              args[4] = SIGCHLD_NUMBER
              args[10] = cgroup_fd.to_u64 if cgroup_fd >= 0
              result = LibC.syscall(SYS_CLONE3, pointerof(args), CLONE_ARGS_SIZE_VER2)
              if result == 0
                # clone3 already placed the child in the cgroup: no need for the cgroup.procs descriptor
                child_exec(prepared, pgroup, -1, error_fd)
              elsif result > 0
                pid = result.to_i32
              else
                failure = Errno.value
                # Docker's default seccomp profile answers ENOSYS, some filters EPERM: use fork from then on.
                @@clone3_refused = true if failure == Errno::ENOSYS || failure == Errno::EPERM
              end
            end

            if pid < 0 && (!use_clone3? || failure == Errno::ENOSYS || failure == Errno::EPERM)
              forked = LibC.fork
              if forked == 0
                child_exec(prepared, pgroup, procs_fd, error_fd)
              end
              if forked > 0
                pid = forked
                failure = Errno::NONE
              else
                failure = Errno.value
              end
            end
          end
        ensure
          LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(previous), nil)
        end

        if pid < 0
          raise clone_error(failure, cgroup_fd >= 0)
        end
        {pid, pidfd}
      end

      private def self.clone_error(errno : Errno, into_cgroup : Bool) : Exception
        if into_cgroup
          case errno
          when Errno::EACCES, Errno::EPERM, Errno::EROFS, Errno::ENOENT
            return ProcessSupervision::Error::Unavailable.new("cgroup is not usable for a new process: #{errno.message}")
          when Errno::EBUSY
            return ProcessSupervision::Error::Busy.new("cgroup cannot hold processes (controllers enabled for its children?): #{errno.message}")
          end
        end
        ProcessSupervision::Error::Native.new("clone3/fork", errno.message, errno.value.to_i64)
      end

      # The child side. Plain system calls only: no allocation, no Crystal runtime, nothing that can raise.
      private def self.child_exec(prepared : ProcessSupervision::POSIX::Spawn::Prepared, pgroup : Int32?, procs_fd : Int32, error_fd : Int32) : NoReturn
        empty = uninitialized LibC::SigsetT
        LibC.sigemptyset(pointerof(empty))
        if procs_fd >= 0
          # writing "0" moves the calling process; the fork path enters the cgroup before it can run anything
          zero = 0x30_u8
          child_fail(error_fd) unless LibC.write(procs_fd, pointerof(zero), 1) == 1
        end
        if group = pgroup
          child_fail(error_fd) unless LibProcessSupervisionLinux.setpgid(0, group) == 0
        end
        number = 1
        while number <= 64
          LibC.signal(number, LibC::SIG_DFL) unless number == 9 || number == 19
          number += 1
        end
        LibC.pthread_sigmask(LibC::SIG_SETMASK, pointerof(empty), nil)
        if directory = prepared.chdir
          child_fail(error_fd) unless LibC.chdir(directory) == 0
        end
        LibC.execve(prepared.path, prepared.argv.pointers, prepared.envp.pointers)
        child_fail(error_fd)
      end

      private def self.child_fail(error_fd : Int32) : NoReturn
        code = Errno.value.value
        LibC.write(error_fd, pointerof(code), 4)
        LibC._exit(127)
      end
    end
  end
{% end %}
