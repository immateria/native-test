{% if flag?(:linux) %}
  require "c/dlfcn"

  private lib LibProcessSupervisionLinux
    fun setpgid(pid : Int32, pgid : Int32) : Int32
    fun posix_spawnattr_init(attr : Void*) : Int32
    fun posix_spawnattr_destroy(attr : Void*) : Int32
    fun posix_spawnattr_setflags(attr : Void*, flags : Int16) : Int32
    fun posix_spawnattr_setpgroup(attr : Void*, pgroup : Int32) : Int32
    fun posix_spawnattr_setsigdefault(attr : Void*, signals : LibC::SigsetT*) : Int32
    fun posix_spawnattr_setsigmask(attr : Void*, signals : LibC::SigsetT*) : Int32
    fun posix_spawn_file_actions_init(actions : Void*) : Int32
    fun posix_spawn_file_actions_destroy(actions : Void*) : Int32
    fun posix_spawn_file_actions_adddup2(actions : Void*, fd : Int32, target : Int32) : Int32
    fun posix_spawn_file_actions_addchdir_np(actions : Void*, path : UInt8*) : Int32
  end

  module ProcessSupervision::Linux
    # :nodoc:
    #
    # Creates a child in one of three ways, best first:
    #
    # * `pidfd_spawn` (glibc 2.39+, looked up at run time so older C libraries still link): posix_spawn semantics, so the
    #   parent's page tables are not copied (a fork's cost grows with the supervisor's heap: 12-22 ms at 512 MiB), plus
    #   the pidfd with the process and, with `posix_spawnattr_setcgroup_np`, CLONE_INTO_CGROUP. Process group, default
    #   signal dispositions, empty mask, standard streams and working directory are attributes and file actions.
    # * clone3 (CLONE_PIDFD, plus CLONE_INTO_CGROUP when a cgroup is given) with the setup done in the child;
    # * fork, where the kernel or a seccomp filter refuses clone3 (a default Docker profile answers ENOSYS).
    #
    # On the clone3 and fork paths the child itself finishes the setup with plain system calls before it execs: it
    # enters the cgroup (fork path), joins or creates its process group, resets every signal disposition and the signal
    # mask, changes directory and execs. It never runs the Crystal runtime and allocates nothing.
    #
    # Why not attach after spawn, or plain posix_spawn: measured natively, writing the pid to cgroup.procs after the child
    # exists lost children in 36-73% of trials under CPU contention, and a pid without a pidfd can be reaped by the
    # runtime before a pidfd is opened. Every path gets the pidfd together with the process, so a child that exits at
    # once can still be supervised.
    module RawSpawn
      private SYS_CLONE3           = 435_i64
      private CLONE_PIDFD          = 0x1000_u64
      private CLONE_INTO_CGROUP   = 0x200000000_u64
      private CLONE_ARGS_SIZE_VER2 =         88_u64
      private SIGCHLD_NUMBER       =         17_u64

      @@clone3_refused = false
      @@clone3_disabled = false
      @@pidfd_spawn_refused = false
      @@pidfd_spawn_disabled = false
      @@last_engine = ""

      private SPAWN_SETPGROUP  = 0x02_i16
      private SPAWN_SETSIGDEF  = 0x04_i16
      private SPAWN_SETSIGMASK = 0x08_i16
      private SPAWN_SETCGROUP  = 0x100_i16

      # glibc 2.39 entry points, looked up at run time (absent from older C libraries and from musl)
      private alias PidfdSpawnFn = Proc(Int32*, UInt8*, Void*, Void*, UInt8**, UInt8**, Int32)
      private alias SetCgroupFn = Proc(Void*, Int32, Int32)
      private alias PidfdGetpidFn = Proc(Int32, Int32)

      private record Symbols, spawn : PidfdSpawnFn, getpid : PidfdGetpidFn, setcgroup : SetCgroupFn?

      @@symbols : Symbols? = nil
      @@symbols_loaded = false

      private def self.symbols : Symbols?
        return @@symbols if @@symbols_loaded
        spawn_ptr = LibC.dlsym(LibC::RTLD_DEFAULT, "pidfd_spawn")
        getpid_ptr = LibC.dlsym(LibC::RTLD_DEFAULT, "pidfd_getpid")
        cgroup_ptr = LibC.dlsym(LibC::RTLD_DEFAULT, "posix_spawnattr_setcgroup_np")
        @@symbols = if spawn_ptr.null? || getpid_ptr.null?
                      nil
                    else
                      Symbols.new(
                        PidfdSpawnFn.new(spawn_ptr, Pointer(Void).null),
                        PidfdGetpidFn.new(getpid_ptr, Pointer(Void).null),
                        cgroup_ptr.null? ? nil : SetCgroupFn.new(cgroup_ptr, Pointer(Void).null))
                    end
        @@symbols_loaded = true
        @@symbols
      end

      # Test hook: forces the clone3/fork engine.
      def self.pidfd_spawn_disabled=(value : Bool)
        @@pidfd_spawn_disabled = value
      end

      # Whether the C library offers pidfd_spawn (and, for *cgroup*, posix_spawnattr_setcgroup_np).
      def self.pidfd_spawn_available?(cgroup : Bool = false) : Bool
        return false unless found = symbols
        cgroup ? !found.setcgroup.nil? : true
      end

      def self.use_pidfd_spawn?(cgroup : Bool) : Bool
        !@@pidfd_spawn_disabled && !@@pidfd_spawn_refused && !@@clone3_disabled && pidfd_spawn_available?(cgroup)
      end

      # The engine the last spawn used: "pidfd_spawn", "clone3" or "fork" (for specs and diagnostics).
      def self.last_engine : String
        @@last_engine
      end

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
      def self.create(prepared : ProcessSupervision::POSIX::Spawn::Prepared, plumbing : ProcessSupervision::POSIX::Spawn::Plumbing, *,
                      cgroup : Path? = nil, pgroup : Int32? = nil) : Pending
        error_reader, error_writer = IO.pipe
        cgroup_fd = -1
        procs_fd = -1
        begin
          if cgroup
            cgroup_fd = open_fd(cgroup.to_s, LibC::O_RDONLY | LibC::O_CLOEXEC)
            procs_fd = open_fd((cgroup / "cgroup.procs").to_s, LibC::O_WRONLY | LibC::O_CLOEXEC)
          end
          spawned = use_pidfd_spawn?(!cgroup.nil?) ? pidfd_spawn(prepared, cgroup_fd, pgroup, plumbing.sources, !cgroup.nil?, error_writer.fd) : nil
          # on the pidfd_spawn path every failure is the call's return code: the error pipe only ever reports EOF
          pid, pidfd = spawned || clone_process(prepared, cgroup_fd, procs_fd, pgroup, error_writer.fd, plumbing.sources)
          Pending.new(pid, pidfd >= 0 ? pidfd : nil, error_reader)
        rescue ex
          error_reader.close rescue nil
          plumbing.abandon
          raise ex
        ensure
          # the parent must not hold the child's ends open, or the other side never sees EOF
          plumbing.release_child_side
          error_writer.close rescue nil
          LibC.close(cgroup_fd) if cgroup_fd >= 0
          LibC.close(procs_fd) if procs_fd >= 0
        end
      end

      # Waits for the exec to succeed or fail, adopts the process into Crystal's reaper and builds the Child. A failed
      # exec reaps the child and raises the stdlib's exception class for the errno.
      def self.complete(pending : Pending, prepared : ProcessSupervision::POSIX::Spawn::Prepared,
                        plumbing : ProcessSupervision::POSIX::Spawn::Plumbing, group : ProcessSupervision::Group,
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
          plumbing.abandon
          if pgroup && pgroup > 0 && (errno == Errno::EPERM || errno == Errno::ESRCH)
            raise ProcessSupervision::Error::Unavailable.new("process group #{pgroup} cannot be joined: #{errno.message}")
          end
          raise ProcessSupervision::POSIX::Spawn.exec_error(prepared.command, errno)
        end

        begin
          handle = ProcessHandle::Linux.adopt_child(pending.pid.to_i64, pidfd)
          ProcessSupervision::Child.new(process, handle, group, plumbing.input, plumbing.output, plumbing.error, plumbing.copies)
        rescue ex
          process.terminate(graceful: false) rescue nil
          process.wait rescue nil
          plumbing.abandon
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

      # Returns nil when the kernel or a seccomp filter refuses the underlying clone3 (ENOSYS), so the caller can use the
      # fork engine; raises for every other failure, classified like the other engines' child-reported errors.
      #
      # glibc 2.39 (Ubuntu 24.04's) leaks the pidfd of a child whose exec failed (sourceware BZ 31695): the call returns
      # the error but leaves the descriptor open, and does not say which it is. The kernel gives the pidfd the lowest free
      # descriptor number, so that number is noted before the call (under a lock shared by every spawn here), and after a
      # failure it is closed if, and only if, it now is a pidfd whose process is gone (`Pid: -1` in its fdinfo). With a
      # fixed C library that descriptor is free or someone else's and is left alone.
      private def self.pidfd_spawn(prepared : ProcessSupervision::POSIX::Spawn::Prepared, cgroup_fd : Int32, pgroup : Int32?,
                                   stdio : StaticArray(Int32, 3), into_cgroup : Bool, any_fd : Int32) : {Int32, Int32}?
        found = symbols.not_nil!
        attributes = StaticArray(UInt64, 64).new(0_u64)
        actions = StaticArray(UInt64, 32).new(0_u64)
        every = uninitialized LibC::SigsetT
        none = uninitialized LibC::SigsetT
        LibC.sigfillset(pointerof(every))
        LibC.sigemptyset(pointerof(none))
        LibProcessSupervisionLinux.posix_spawnattr_init(pointerof(attributes))
        LibProcessSupervisionLinux.posix_spawn_file_actions_init(pointerof(actions))
        begin
          LibProcessSupervisionLinux.posix_spawnattr_setsigdefault(pointerof(attributes), pointerof(every))
          LibProcessSupervisionLinux.posix_spawnattr_setsigmask(pointerof(attributes), pointerof(none))
          flags = SPAWN_SETSIGDEF | SPAWN_SETSIGMASK
          if group = pgroup
            flags |= SPAWN_SETPGROUP
            LibProcessSupervisionLinux.posix_spawnattr_setpgroup(pointerof(attributes), group)
          end
          if into_cgroup
            flags |= SPAWN_SETCGROUP
            found.setcgroup.not_nil!.call(pointerof(attributes).as(Void*), cgroup_fd)
          end
          LibProcessSupervisionLinux.posix_spawnattr_setflags(pointerof(attributes), flags)
          3.times do |target|
            # sources are all >= 3 (see Plumbing) and close-on-exec; dup2 clears that flag on the target
            source = stdio[target]
            LibProcessSupervisionLinux.posix_spawn_file_actions_adddup2(pointerof(actions), source, target) if source >= 0
          end
          prepared.chdir.try do |directory|
            rc = LibProcessSupervisionLinux.posix_spawn_file_actions_addchdir_np(pointerof(actions), directory)
            raise ProcessSupervision::POSIX::Spawn.exec_error(prepared.command, Errno.new(rc)) unless rc == 0
          end

          pidfd = -1_i32
          rc = @@pidfd_spawn_lock.synchronize do
            probe = lowest_free_fd(any_fd)
            result = Crystal::System::Process.lock_write do
              found.spawn.call(pointerof(pidfd), prepared.path.to_unsafe, pointerof(actions).as(Void*),
                pointerof(attributes).as(Void*), prepared.argv.pointers, prepared.envp.pointers)
            end
            close_leaked_pidfd(probe) unless result == 0
            result
          end
          if rc == 0
            pid = found.getpid.call(pidfd)
            if pid <= 0
              errno = Errno.value
              LibC.close(pidfd)
              raise ProcessSupervision::Error::Native.new("pidfd_getpid", errno.message, errno.value.to_i64)
            end
            @@last_engine = "pidfd_spawn"
            return {pid, pidfd}
          end

          errno = Errno.new(rc)
          if errno == Errno::ENOSYS
            @@pidfd_spawn_refused = true
            return nil
          end
          if into_cgroup && errno == Errno::EBUSY
            raise ProcessSupervision::Error::Busy.new("cgroup cannot hold processes (controllers enabled for its children?): #{errno.message}")
          end
          if pgroup && pgroup > 0 && (errno == Errno::EPERM || errno == Errno::ESRCH)
            raise ProcessSupervision::Error::Unavailable.new("process group #{pgroup} cannot be joined: #{errno.message}")
          end
          raise ProcessSupervision::POSIX::Spawn.exec_error(prepared.command, errno)
        ensure
          LibProcessSupervisionLinux.posix_spawnattr_destroy(pointerof(attributes))
          LibProcessSupervisionLinux.posix_spawn_file_actions_destroy(pointerof(actions))
        end
      end

      @@pidfd_spawn_lock = Thread::Mutex.new
      @@leaked_pidfds_closed = Atomic(Int32).new(0)

      # How many pidfds a failed pidfd_spawn left open and this module closed (for specs and diagnostics).
      def self.leaked_pidfds_closed : Int32
        @@leaked_pidfds_closed.get
      end

      private def self.lowest_free_fd(any_fd : Int32) : Int32
        probe = LibC.fcntl(any_fd, ProcessSupervision::POSIX::Spawn::F_DUPFD_CLOEXEC, 0)
        return -1 if probe < 0
        LibC.close(probe)
        probe
      end

      # Plain system calls only (this runs under Thread::Mutexes and must not yield to another fiber).
      private def self.close_leaked_pidfd(fd : Int32) : Nil
        return if fd < 0
        target = StaticArray(UInt8, 64).new(0_u8)
        length = LibC.readlink("/proc/self/fd/#{fd}", target.to_unsafe, target.size - 1)
        return unless length > 0 && String.new(target.to_unsafe, length) == "anon_inode:[pidfd]"
        info = LibC.open("/proc/self/fdinfo/#{fd}", LibC::O_RDONLY | LibC::O_CLOEXEC)
        return if info < 0
        text = StaticArray(UInt8, 512).new(0_u8)
        read = begin
          LibC.read(info, text.to_unsafe, text.size - 1)
        ensure
          LibC.close(info)
        end
        return unless read > 0 && String.new(text.to_unsafe, read).includes?("\nPid:\t-1\n")
        LibC.close(fd)
        @@leaked_pidfds_closed.add(1)
      end

      private def self.clone_process(prepared : ProcessSupervision::POSIX::Spawn::Prepared, cgroup_fd : Int32, procs_fd : Int32,
                                     pgroup : Int32?, error_fd : Int32, stdio : StaticArray(Int32, 3)) : {Int32, Int32}
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
                child_exec(prepared, pgroup, -1, error_fd, stdio)
              elsif result > 0
                pid = result.to_i32
                @@last_engine = "clone3"
              else
                failure = Errno.value
                # Docker's default seccomp profile answers ENOSYS, some filters EPERM: use fork from then on.
                @@clone3_refused = true if failure == Errno::ENOSYS || failure == Errno::EPERM
              end
            end

            if pid < 0 && (!use_clone3? || failure == Errno::ENOSYS || failure == Errno::EPERM)
              forked = LibC.fork
              if forked == 0
                child_exec(prepared, pgroup, procs_fd, error_fd, stdio)
              end
              if forked > 0
                pid = forked
                failure = Errno::NONE
                @@last_engine = "fork"
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
      private def self.child_exec(prepared : ProcessSupervision::POSIX::Spawn::Prepared, pgroup : Int32?, procs_fd : Int32,
                                  error_fd : Int32, stdio : StaticArray(Int32, 3)) : NoReturn
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
        target = 0
        while target < 3
          source = stdio[target]
          # sources are all >= 3 (see Plumbing), so no dup2 can overwrite a later source
          child_fail(error_fd) if source >= 0 && LibC.dup2(source, target) < 0
          target += 1
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
