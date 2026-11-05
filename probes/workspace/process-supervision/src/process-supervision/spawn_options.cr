module ProcessSupervision
  # Process attributes beyond command, arguments, environment, directory and standard streams. Every spawn method takes
  # one as `options:`. An option a backend cannot honour raises `Error::Unsupported` before anything is created, never
  # silently ignored. Which backend honours what:
  #
  # | option                | Linux                      | macOS              | Windows Job          |
  # |-----------------------|----------------------------|--------------------|----------------------|
  # | `new_session`         | yes (`setsid`)             | yes (`SETSID`)     | -                    |
  # | `extra_fds`           | yes                        | yes                | yes (handle values in `PROCESS_SUPERVISION_HANDLES`) |
  # | `ipc`                 | yes (socket on fd 3+)      | yes                | -                    |
  # | `uid`/`gid`/`groups`  | yes (needs privilege)      | -                  | -                    |
  # | `umask`               | yes                        | -                  | -                    |
  # | `rlimits`             | yes                        | -                  | - (use Job limits)   |
  # | `parent_death_signal` | yes                        | -                  | - (Job kill-on-close)|
  # | `no_new_privileges`   | yes                        | -                  | -                    |
  # | `namespaces`          | yes (clone3; needs privilege or a user namespace) | - | -              |
  # | `console_group`       | -                          | -                  | yes (`CREATE_NEW_PROCESS_GROUP`, needed for `request_stop`) |
  # | `hide_window`         | -                          | -                  | yes (`CREATE_NO_WINDOW`) |
  #
  # On Linux the options only `pidfd_spawn` can express (session, extra descriptors, IPC) keep it as the engine; the
  # others need code in the child before exec and use clone3 (or fork).
  class SpawnOptions
    # Resource limits a child can be started with (`setrlimit` in the child before exec).
    enum Rlimit
      Cpu
      Fsize
      Data
      Stack
      Core
      Nproc
      Nofile
      Memlock
      AddressSpace

      # The Linux resource number.
      def native : Int32
        case self
        in .cpu?           then 0
        in .fsize?         then 1
        in .data?          then 2
        in .stack?         then 3
        in .core?          then 4
        in .nproc?         then 6
        in .nofile?        then 7
        in .memlock?       then 8
        in .address_space? then 9
        end
      end
    end

    # Linux namespaces the child is created in (clone3 flags).
    @[Flags]
    enum Namespace : UInt64
      Mount   = 0x00020000
      Uts     = 0x04000000
      Ipc     = 0x08000000
      User    = 0x10000000
      Pid     = 0x20000000
      Network = 0x40000000
    end

    UNLIMITED = UInt64::MAX

    # Start the child in a new session (and so a new process group, led by the child, with no controlling terminal).
    # Only for a child that leads its own group (`spawn_leader`, `ProcessSupervision.spawn`, a cgroup or a Job).
    property new_session : Bool = false
    # Descriptors to pass on: child descriptor number (3 and up) => the parent's descriptor. Everything else stays closed.
    property extra_fds : Hash(Int32, IO::FileDescriptor) = {} of Int32 => IO::FileDescriptor
    # A connected socket pair: the child's end on the first free descriptor from 3 (announced in
    # `PROCESS_SUPERVISION_IPC_FD`), the parent's end as `Child#ipc`.
    property ipc : Bool = false
    property uid : UInt32? = nil
    property gid : UInt32? = nil
    property groups : Array(UInt32)? = nil
    property umask : UInt32? = nil
    # resource => {soft, hard}; `UNLIMITED` for no limit
    property rlimits : Hash(Rlimit, Tuple(UInt64, UInt64)) = {} of Rlimit => Tuple(UInt64, UInt64)
    # Signal the child gets when the thread that created it exits (Linux `PR_SET_PDEATHSIG`). Note: it is tied to the
    # creating *thread*, not the process; in a multi-threaded runtime prefer `ProcessSupervision::Lifeline`.
    property parent_death_signal : Signal? = nil
    property no_new_privileges : Bool = false
    property namespaces : Namespace = Namespace::None
    property console_group : Bool = false
    property hide_window : Bool = false

    def initialize
    end

    # Whether these options need code in the child between fork and exec (so not `pidfd_spawn` / `posix_spawn`).
    def needs_child_setup? : Bool
      !@uid.nil? || !@gid.nil? || !@groups.nil? || !@umask.nil? || !@rlimits.empty? || !@parent_death_signal.nil? ||
        @no_new_privileges || !@namespaces.none?
    end

    def default? : Bool
      !@new_session && @extra_fds.empty? && !@ipc && !needs_child_setup? && !@console_group && !@hide_window
    end

    # Raises `Error::Unsupported` naming the first option this backend cannot honour.
    def check_supported!(backend : String, *, new_session = true, extra_fds = true, ipc = true, credentials = false,
                         umask = false, rlimits = false, parent_death_signal = false, no_new_privileges = false,
                         namespaces = false, console_group = false, hide_window = false) : Nil
      refuse(backend, "new_session") if @new_session && !new_session
      refuse(backend, "extra_fds") if !@extra_fds.empty? && !extra_fds
      refuse(backend, "ipc") if @ipc && !ipc
      refuse(backend, "uid/gid/groups") if (@uid || @gid || @groups) && !credentials
      refuse(backend, "umask") if @umask && !umask
      refuse(backend, "rlimits") if !@rlimits.empty? && !rlimits
      refuse(backend, "parent_death_signal") if @parent_death_signal && !parent_death_signal
      refuse(backend, "no_new_privileges") if @no_new_privileges && !no_new_privileges
      refuse(backend, "namespaces") if !@namespaces.none? && !namespaces
      refuse(backend, "console_group") if @console_group && !console_group
      refuse(backend, "hide_window") if @hide_window && !hide_window
      @extra_fds.each_key do |target|
        raise ArgumentError.new("extra_fds target #{target} must be 3 or above") if target < 3
      end
    end

    private def refuse(backend : String, option : String) : NoReturn
      raise Error::Unsupported.new("spawn option #{option} is not supported by #{backend}")
    end
  end
end
