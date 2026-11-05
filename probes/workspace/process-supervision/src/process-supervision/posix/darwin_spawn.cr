{% if flag?(:darwin) %}
  private lib LibProcessSupervisionDarwin
    fun posix_spawn(pid : Int32*, path : UInt8*, file_actions : Void*, attrp : Void*, argv : UInt8**, envp : UInt8**) : Int32
    fun posix_spawnattr_init(attr : Void*) : Int32
    fun posix_spawnattr_destroy(attr : Void*) : Int32
    fun posix_spawnattr_setflags(attr : Void*, flags : Int16) : Int32
    fun posix_spawnattr_setpgroup(attr : Void*, pgroup : Int32) : Int32
    fun posix_spawnattr_setsigdefault(attr : Void*, signals : Void*) : Int32
    fun posix_spawnattr_setsigmask(attr : Void*, signals : Void*) : Int32
    fun posix_spawn_file_actions_init(actions : Void*) : Int32
    fun posix_spawn_file_actions_destroy(actions : Void*) : Int32
    fun posix_spawn_file_actions_addinherit_np(actions : Void*, fd : Int32) : Int32
    fun posix_spawn_file_actions_adddup2(actions : Void*, fd : Int32, target : Int32) : Int32
    fun posix_spawn_file_actions_addchdir_np(actions : Void*, path : UInt8*) : Int32
  end

  module ProcessSupervision::POSIX
    # :nodoc:
    #
    # macOS has no clone3 and no cgroups; posix_spawn can do what a supervisor needs before the program runs, in one call:
    # its own or an existing process group, default signal dispositions and an empty mask, descriptors other than 0-2
    # closed (POSIX_SPAWN_CLOEXEC_DEFAULT), the working directory. Measured natively (all five hosted macOS runners):
    # SETPGROUP puts the child in its group before the call returns (300 of 300; a parent's setpgid after exec fails with
    # EACCES 300 of 300), and every failure comes back as the call's return code with nothing to reap.
    #
    # The child is started suspended (POSIX_SPAWN_START_SUSPENDED: it exists and has run no instruction) so that the exit
    # watch of its ProcessHandle::Kqueue exists before it can exit — registering on an exited process fails with ESRCH —
    # and then resumed with SIGCONT.
    module DarwinSpawn
      private SPAWN_SETPGROUP       = 0x0002_i16
      private SPAWN_SETSIGDEF       = 0x0004_i16
      private SPAWN_SETSIGMASK      = 0x0008_i16
      private SPAWN_START_SUSPENDED = 0x0080_i16
      private SPAWN_SETSID          = 0x0400_i16
      private SPAWN_CLOEXEC_DEFAULT = 0x4000_i16

      def self.launch(prepared : Spawn::Prepared, pgroup : Int32?, plumbing : Spawn::Plumbing) : {Int32, ::Process, ProcessHandle}
        pid = begin
          create_suspended(prepared, pgroup, plumbing)
        rescue ex
          plumbing.abandon
          raise ex
        ensure
          # the parent must not hold the child's ends open, or the other side never sees EOF
          plumbing.release_child_side
        end
        process = Spawn.adopt(pid)
        handle = begin
          ProcessHandle::Kqueue.adopt_child(pid.to_i64)
        rescue ex
          LibC.kill(pid, Signal::KILL.value)
          process.wait rescue nil
          plumbing.abandon
          raise ex
        end

        if LibC.kill(pid, Signal::CONT.value) != 0
          errno = Errno.value
          LibC.kill(pid, Signal::KILL.value)
          process.wait rescue nil
          handle.close rescue nil
          plumbing.abandon
          raise ProcessSupervision::Error::Native.new("kill(SIGCONT)", errno.message, errno.value.to_i64)
        end
        {pid, process, handle}
      end

      private def self.create_suspended(prepared : Spawn::Prepared, pgroup : Int32?, plumbing : Spawn::Plumbing) : Int32
        attributes = StaticArray(UInt64, 64).new(0_u64)
        actions = StaticArray(UInt64, 64).new(0_u64)
        every = StaticArray(UInt64, 32).new(0_u64)
        none = StaticArray(UInt64, 32).new(0_u64)
        LibProcessSupervisionDarwin.posix_spawnattr_init(pointerof(attributes))
        LibProcessSupervisionDarwin.posix_spawn_file_actions_init(pointerof(actions))
        begin
          LibC.sigfillset(pointerof(every).as(LibC::SigsetT*))
          LibC.sigemptyset(pointerof(none).as(LibC::SigsetT*))
          LibProcessSupervisionDarwin.posix_spawnattr_setsigdefault(pointerof(attributes), pointerof(every))
          LibProcessSupervisionDarwin.posix_spawnattr_setsigmask(pointerof(attributes), pointerof(none))
          flags = SPAWN_START_SUSPENDED | SPAWN_SETSIGDEF | SPAWN_SETSIGMASK | SPAWN_CLOEXEC_DEFAULT
          if prepared.options.new_session
            # a new session is also a new process group led by the child
            flags |= SPAWN_SETSID
          elsif group = pgroup
            flags |= SPAWN_SETPGROUP
            LibProcessSupervisionDarwin.posix_spawnattr_setpgroup(pointerof(attributes), group)
          end
          LibProcessSupervisionDarwin.posix_spawnattr_setflags(pointerof(attributes), flags)
          # CLOEXEC_DEFAULT closes everything that is not named here: inherit 0-2 unless redirected
          3.times do |target|
            source = plumbing.sources[target]
            if source >= 0
              LibProcessSupervisionDarwin.posix_spawn_file_actions_adddup2(pointerof(actions), source, target)
            else
              LibProcessSupervisionDarwin.posix_spawn_file_actions_addinherit_np(pointerof(actions), target)
            end
          end
          plumbing.extra_count.times do |index|
            LibProcessSupervisionDarwin.posix_spawn_file_actions_adddup2(pointerof(actions), plumbing.extra_sources[index],
              plumbing.extra_targets[index])
          end
          prepared.chdir.try do |directory|
            rc = LibProcessSupervisionDarwin.posix_spawn_file_actions_addchdir_np(pointerof(actions), directory)
            raise Spawn.exec_error(prepared.command, Errno.new(rc)) unless rc == 0
          end

          pid = 0_i32
          rc = Crystal::System::Process.lock_write do
            LibProcessSupervisionDarwin.posix_spawn(
              pointerof(pid), prepared.path, pointerof(actions), pointerof(attributes),
              prepared.argv.pointers, prepared.envp.pointers)
          end
          if rc != 0
            errno = Errno.new(rc)
            if pgroup && pgroup > 0 && (errno == Errno::EPERM || errno == Errno::ESRCH)
              raise ProcessSupervision::Error::Unavailable.new("process group #{pgroup} cannot be joined: #{errno.message}")
            end
            raise Spawn.exec_error(prepared.command, errno)
          end
          pid
        ensure
          LibProcessSupervisionDarwin.posix_spawnattr_destroy(pointerof(attributes))
          LibProcessSupervisionDarwin.posix_spawn_file_actions_destroy(pointerof(actions))
        end
      end
    end
  end
{% end %}
