{% if flag?(:linux) %}
  module ProcessSupervision::Linux
    class CgroupV2
      # Resource limits written to this cgroup's interface files. Each needs its controller enabled in the parent's
      # `cgroup.subtree_control` (see `CgroupV2.enable_controllers`); a missing file raises `Error::Unavailable` naming it.
      record Limits,
        memory_max : UInt64? = nil,
        memory_high : UInt64? = nil,
        swap_max : UInt64? = nil,
        # share of one CPU, e.g. 150.0 for one and a half CPUs (cpu.max quota/period with a 100 ms period)
        cpu_percent : Float64? = nil,
        cpu_weight : Int32? = nil,
        pids_max : Int64? = nil

      record Stats,
        cpu_usage : Time::Span?,
        cpu_user : Time::Span?,
        cpu_system : Time::Span?,
        memory_current : UInt64?,
        memory_peak : UInt64?,
        pids_current : Int64?

      # memory.events counters (cumulative): how often the cgroup was throttled at memory.high, hit memory.max, and how
      # many OOM events and OOM kills happened in it.
      record MemoryEvents, high : Int64, max : Int64, oom : Int64, oom_kill : Int64

      # Enables *controllers* for the children of *parent* (writes `+memory +cpu ...` to its `cgroup.subtree_control`).
      # This changes the host's controller policy, which nothing else here does: call it only for a parent that is
      # delegated to this process. The kernel refuses (EBUSY) while *parent* itself holds processes ("no internal
      # processes"). Returns the controllers enabled afterwards.
      def self.enable_controllers(parent : Path | String, controllers : Enumerable(String) = %w[memory cpu pids io]) : Array(String)
        base = Path[parent]
        available = File.read(base / "cgroup.controllers").split
        wanted = controllers.select { |name| available.includes?(name) }
        unless wanted.empty?
          File.write(base / "cgroup.subtree_control", wanted.map { |name| "+#{name}" }.join(' '))
        end
        File.read(base / "cgroup.subtree_control").split
      rescue ex : File::AccessDeniedError
        raise ProcessSupervision::Error::Unavailable.new("cgroup.subtree_control is not writable: #{ex.message}")
      rescue ex : File::Error
        if ex.os_error == Errno::EBUSY
          raise ProcessSupervision::Error::Busy.new("#{parent} holds processes, so controllers cannot be enabled below it")
        end
        raise ProcessSupervision::Error::Native.new("write(cgroup.subtree_control)", ex.message || "failed")
      end

      def limits=(limits : Limits) : Limits
        limits.memory_max.try { |bytes| write_interface("memory.max", bytes.to_s) }
        limits.memory_high.try { |bytes| write_interface("memory.high", bytes.to_s) }
        limits.swap_max.try { |bytes| write_interface("memory.swap.max", bytes.to_s) }
        limits.cpu_percent.try do |percent|
          raise ArgumentError.new("cpu_percent must be positive") unless percent > 0
          write_interface("cpu.max", "#{(percent * 1000).round.to_i64} 100000")
        end
        limits.cpu_weight.try do |weight|
          raise ArgumentError.new("cpu_weight must be 1..10000") unless 1 <= weight <= 10_000
          write_interface("cpu.weight", weight.to_s)
        end
        limits.pids_max.try { |count| write_interface("pids.max", count.to_s) }
        limits
      end

      def stats : Stats
        cpu = read_keyed("cpu.stat")
        micro = ->(key : String) { cpu[key]?.try(&.microseconds) }
        Stats.new(
          cpu_usage: micro.call("usage_usec"), cpu_user: micro.call("user_usec"), cpu_system: micro.call("system_usec"),
          memory_current: read_number("memory.current").try(&.to_u64), memory_peak: read_number("memory.peak").try(&.to_u64),
          pids_current: read_number("pids.current"))
      end

      # nil when the memory controller is not enabled for this cgroup.
      def memory_events : MemoryEvents?
        events = read_keyed("memory.events")
        return nil if events.empty?
        MemoryEvents.new(events["high"]? || 0_i64, events["max"]? || 0_i64, events["oom"]? || 0_i64, events["oom_kill"]? || 0_i64)
      end

      # Every process in this cgroup and its descendants.
      def members : Array(Int64)
        pids = [] of Int64
        each_cgroup(@path) do |directory|
          File.each_line(directory / "cgroup.procs") { |line| line.to_i64?.try { |pid| pids << pid } } rescue nil
        end
        pids
      end

      # Sends *signal* to every member through a pidfd, after checking the process is still in this subtree (a pid
      # read from cgroup.procs could have been recycled before the pidfd was opened).
      def signal(signal : Signal) : Nil
        @mutex.synchronize { check_open_locked }
        members.each do |pid|
          handle = begin
            ProcessHandle.open(pid)
          rescue ProcessHandle::Error
            next
          end
          begin
            next unless member_of_subtree?(pid)
            handle.signal(signal)
          rescue ProcessHandle::Error
          ensure
            handle.close rescue nil
          end
        end
      end

      # Freezes the whole subtree atomically (cgroup.freeze) and waits until the kernel reports it frozen.
      def suspend : Nil
        write_interface("cgroup.freeze", "1")
        ProcessSupervision::Readiness.poll(5.seconds) { frozen? }
      end

      def resume : Nil
        write_interface("cgroup.freeze", "0")
        ProcessSupervision::Readiness.poll(5.seconds) { !frozen? }
      end

      def frozen? : Bool
        read_keyed("cgroup.events")["frozen"]? == 1
      end

      def request_stop : Nil
        resume if frozen?
        signal(Signal::CONT)
        signal(Signal::TERM)
      end

      private def member_of_subtree?(pid : Int64) : Bool
        mount = CgroupV2.mountpoint
        return true unless mount
        relative = @path.to_s.lchop(mount.to_s)
        File.read("/proc/#{pid}/cgroup").each_line.any? do |line|
          line.starts_with?("0::") && (line[3..] == relative || line[3..].starts_with?("#{relative}/"))
        end
      rescue File::Error
        false
      end

      private def each_cgroup(directory : Path, &block : Path ->) : Nil
        yield directory
        Dir.each_child(directory) do |name|
          child = directory / name
          each_cgroup(child, &block) if File.directory?(child)
        end
      rescue File::Error
      end

      # The write happens outside the controller's Thread::Mutex (blocking file I/O may move the fiber to another
      # thread under execution contexts).
      private def write_interface(name : String, value : String) : Nil
        @mutex.synchronize { check_open_locked }
        file = @path / name
        raise ProcessSupervision::Error::Unavailable.new("#{name} is missing: enable its controller in the parent") unless File.exists?(file)
        File.write(file, value)
      rescue ex : File::AccessDeniedError
        raise ProcessSupervision::Error::Unavailable.new("#{name} is not writable: #{ex.message}")
      rescue ex : File::Error
        raise ProcessSupervision::Error::Native.new("write(#{name})", ex.message || "failed")
      end

      private def read_keyed(name : String) : Hash(String, Int64)
        values = {} of String => Int64
        File.each_line(@path / name) do |line|
          key, _, value = line.partition(' ')
          value.to_i64?.try { |number| values[key] = number }
        end
        values
      rescue File::Error
        {} of String => Int64
      end

      private def read_number(name : String) : Int64?
        File.read(@path / name).strip.to_i64?
      rescue File::Error
        nil
      end
    end

    # Asks systemd for a cgroup this process may manage (a transient scope with `Delegate=yes`), instead of hoping one
    # was delegated. Runs `systemd-run --scope` (system manager as root, the user's manager otherwise) around a keeper
    # process that holds the scope open, moves the keeper into `keeper/` so the scope's own directory is free for child
    # cgroups (and controllers), and returns the scope's path. `close` ends the keeper; systemd then removes the scope.
    # Experimental: needs `systemd-run` and a reachable manager (a user manager needs a session or lingering).
    class SystemdScope
      getter path : Path
      getter unit : String

      def self.acquire(name : String = "process-supervision-#{::Process.pid}-#{Random.new.hex(4)}") : SystemdScope
        runner = ::Process.find_executable("systemd-run")
        raise ProcessSupervision::Error::Unavailable.new("systemd-run is not installed") unless runner
        user = LibC.getuid != 0
        unit = "#{name}.scope"
        args = [] of String
        args << "--user" if user
        args.concat(["--scope", "--quiet", "--collect", "-p", "Delegate=yes", "--unit", unit, "--", "/bin/sh", "-c", "echo ready; exec sleep 2147483647"])
        keeper = ::Process.new(runner, args, output: ::Process::Redirect::Pipe, error: ::Process::Redirect::Pipe)
        line = keeper.output.gets
        unless line == "ready"
          # stop it first: if the scope command did start, it holds the error pipe open and the read would not end
          keeper.terminate rescue nil
          keeper.wait rescue nil
          message = keeper.error.gets_to_end rescue ""
          raise ProcessSupervision::Error::Unavailable.new("systemd-run could not create #{unit}: #{message.strip}")
        end
        path = scope_path(keeper.pid)
        unless path
          keeper.terminate rescue nil
          keeper.wait rescue nil
          raise ProcessSupervision::Error::Unavailable.new("the cgroup of #{unit} was not found")
        end
        begin
          Dir.mkdir(path / "keeper")
          File.write(path / "keeper" / "cgroup.procs", keeper.pid.to_s)
        rescue ex : File::Error
          keeper.terminate rescue nil
          keeper.wait rescue nil
          raise ProcessSupervision::Error::Unavailable.new("#{unit} is not delegated to this user: #{ex.message}")
        end
        # Moving a process between cgroups needs write access to cgroup.procs of their closest common ancestor. A
        # supervisor that is not itself inside the user's systemd tree (a system service, a CI job) gets EACCES for
        # every child it spawns into the scope, so refuse here rather than at the first spawn.
        unless can_migrate_into?(path)
          keeper.terminate rescue nil
          keeper.wait rescue nil
          raise ProcessSupervision::Error::Unavailable.new(
            "#{unit} was created, but this process cannot move children into it: cgroup.procs of the common " \
            "ancestor of its own cgroup and the scope is not writable (run the supervisor inside the user's " \
            "systemd session, or as root)")
        end
        new(path, unit, keeper)
      end

      private def self.can_migrate_into?(target : Path) : Bool
        own = CgroupV2.current_path
        return false unless own
        ancestor = own
        until target.to_s == ancestor.to_s || target.to_s.starts_with?("#{ancestor.to_s.chomp('/')}/")
          parent = ancestor.parent
          return false if parent == ancestor
          ancestor = parent
        end
        LibC.access((ancestor / "cgroup.procs").to_s, LibC::W_OK) == 0
      end

      def initialize(@path : Path, @unit : String, @keeper : ::Process)
      end

      def close : Nil
        @keeper.terminate rescue nil
        @keeper.wait rescue nil
      end

      # the keeper (systemd-run execs the shell, which execs sleep) is in the scope's cgroup
      private def self.scope_path(pid : Int64) : Path?
        mount = CgroupV2.mountpoint
        return unless mount
        File.read("/proc/#{pid}/cgroup").each_line do |line|
          return mount / line[3..].lchop('/') if line.starts_with?("0::")
        end
        nil
      rescue File::Error
        nil
      end
    end
  end
{% end %}
