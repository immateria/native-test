{% if flag?(:linux) %}
  private lib LibProcessSupervisionInotify
    fun inotify_init1(flags : Int32) : Int32
    fun inotify_add_watch(fd : Int32, path : UInt8*, mask : UInt32) : Int32
  end

  module ProcessSupervision::Linux
    # Controller for one non-root cgroup-v2 subtree.
    #
    # This is stronger than a POSIX process group: descendants inherit cgroup
    # membership, `cgroup.events` reports recursive population, and
    # `cgroup.kill` atomically kills the subtree while accounting for
    # concurrent forks/migrations. Creating or opening a cgroup requires an
    # already-mounted v2 hierarchy; creating one also requires a delegated or
    # otherwise writable parent.
    class CgroupV2 < ProcessSupervision::Group
      getter path : Path
      getter owned : Bool

      @mutex = Thread::Mutex.new
      @closed = false
      @killed = false

      # Whether a cgroup-v2 hierarchy is mounted. This says nothing about whether this process may create or enter a
      # cgroup there: a default Docker container mounts it read-only. Use `usable?` or `delegated_parent` for that.
      def self.available? : Bool
        !mount_entries.empty?
      end

      # Whether `parent` accepts a new child cgroup right now (creates and removes a probe). Detection by trying is the
      # only reliable test: measured natively, the same mount was writable for a systemd `Delegate=yes` unit and a user
      # manager's units, read-only in a default Docker container and `EACCES` for an ordinary service or user.
      def self.usable?(parent : Path | String) : Bool
        probe = create(parent, ".process-supervision-probe-#{::Process.pid}-#{Random.new.hex(4)}")
        probe.close
        true
      rescue ProcessSupervision::Error | ArgumentError | File::Error
        false
      end

      # The first directory, starting with this process's own cgroup and going up to (not including) the machine's
      # hierarchy root, in which a child cgroup can be created: where a service manager delegated one to this process
      # (systemd Delegate=yes, a user manager's units, a privileged container's cgroup namespace root). nil when nothing
      # is delegated; the caller then falls back to a process group.
      def self.delegated_parent : Path?
        current = current_path
        mount = mountpoint
        return unless current && mount
        initial = initial_cgroup_namespace?
        path = current
        loop do
          at_mount = path == mount
          break if at_mount && initial
          return path if usable?(path)
          break if at_mount
          parent = path.parent
          break if parent == path || !within_mount?(parent.to_s, mount.to_s)
          path = parent
        end
        nil
      end

      # Finds the cgroup-v2 mount that exposes the current process. If the
      # process path cannot be mapped, returns the first visible v2 mount.
      def self.mountpoint : Path?
        active_mount_entry.try(&.[0]) || mount_entries.first?.try(&.[0])
      end

      # Returns the current process's directory in the visible cgroup-v2 mount.
      # mountinfo may expose only a subtree of the hierarchy, so account for the
      # mount's cgroup root instead of blindly appending /proc/self/cgroup.
      def self.current_path : Path?
        cgroup_path = current_cgroup_path
        return unless cgroup_path
        entry = best_mount_entry(cgroup_path)
        return unless entry
        mount, hierarchy_root = entry
        relative = relative_to_mount_root(cgroup_path, hierarchy_root)
        return unless relative
        relative.empty? ? mount : mount / relative
      end

      # Opens an existing cgroup. Root cgroups are rejected deliberately: a
      # supervision object must never make the hierarchy root a kill target.
      def self.open(path : Path | String, *, owned : Bool = false) : self
        mount = mountpoint
        raise ProcessSupervision::Error::Unavailable.new("cgroup v2 is not mounted") unless mount

        resolved = File.realpath(path)
        entry = mount_entry_for(resolved)
        unless entry
          raise ArgumentError.new("cgroup path #{resolved} is outside every visible cgroup-v2 mount")
        end
        resolved_mount = File.realpath(entry[0])
        # The machine's hierarchy root is never a supervision target. Inside a private cgroup namespace (a container) the
        # mount root is only the container's own cgroup, which is an ordinary cgroup on the host; killing it kills the
        # caller too, as for any cgroup the caller is in.
        if resolved == resolved_mount && entry[1] == "/" && initial_cgroup_namespace?
          raise ArgumentError.new("refusing to supervise the cgroup-v2 hierarchy root")
        end

        validate_interface!(resolved)
        new(Path[resolved], owned)
      rescue ex : File::NotFoundError
        raise ProcessSupervision::Error::Unavailable.new("cgroup v2 path is unavailable: #{ex.message}")
      rescue ex : File::AccessDeniedError
        raise ProcessSupervision::Error::Unavailable.new("cgroup v2 path is inaccessible: #{ex.message}")
      end

      # Creates a single child cgroup below an explicitly supplied parent. The
      # caller is responsible for choosing a parent delegated to it by the host
      # or service manager. This method never changes subtree controller policy.
      def self.create(parent : Path | String, name : String) : self
        validate_name!(name)
        mount = mountpoint
        raise ProcessSupervision::Error::Unavailable.new("cgroup v2 is not mounted") unless mount

        resolved_parent = File.realpath(parent)
        unless mount_entry_for(resolved_parent)
          raise ArgumentError.new("cgroup parent #{resolved_parent} is outside every visible cgroup-v2 mount")
        end

        child = Path[resolved_parent] / name
        Dir.mkdir(child)
        begin
          validate_interface!(child.to_s)
          new(child, true)
        rescue ex
          Dir.delete(child) rescue nil
          raise ex
        end
      rescue ex : File::AccessDeniedError
        raise ProcessSupervision::Error::Unavailable.new("cgroup parent is not delegated/writable: #{ex.message}")
      rescue ex : File::NotFoundError
        raise ProcessSupervision::Error::Unavailable.new("cgroup parent is unavailable: #{ex.message}")
      rescue ex : File::Error
        # a read-only cgroup mount (a default Docker container) is EROFS, which the stdlib maps to a plain File::Error
        if ex.os_error == Errno::EROFS || ex.os_error == Errno::EPERM
          raise ProcessSupervision::Error::Unavailable.new("cgroup parent is read-only or not permitted: #{ex.message}")
        end
        raise ex
      end

      private def initialize(@path : Path, @owned : Bool)
      end

      def mechanism : ProcessSupervision::Mechanism
        ProcessSupervision::Mechanism::CgroupV2
      end

      def kill_on_close? : Bool
        false
      end

      # cgroup v2 has a strong recursive SIGKILL primitive but no equivalent
      # recursive cooperative-termination primitive.
      def soft_termination? : Bool
        false
      end

      # Numeric cgroup migration is deliberately explicit. `cgroup.procs` names
      # a process by PID, not a pidfd; callers needing race-free initial
      # containment should use a spawn mechanism that enters the cgroup before
      # the target is allowed to execute rather than calling this after the fact.
      def attach(pid : Int) : Nil
        value = pid.to_i64
        raise ArgumentError.new("pid must be positive") unless value > 0
        @mutex.synchronize do
          check_open_locked
          CgroupV2.raw_write(@path / "cgroup.procs", "#{value}\n")
        end
      rescue ex : File::AccessDeniedError
        raise ProcessSupervision::Error::Unavailable.new("cgroup.procs is not delegated/writable: #{ex.message}")
      rescue ex : File::Error
        raise ProcessSupervision::Error::Native.new("write(cgroup.procs)", ex.message || "cgroup migration failed")
      end

      # Spawns a direct executable/argv child that is in this cgroup before it executes a single instruction, so none of
      # its descendants can be created outside it (clone3 with CLONE_INTO_CGROUP; where clone3 is refused, a fork whose
      # child enters the cgroup itself before exec). The child starts with default signal dispositions and an empty
      # signal mask, inherits stdio 0-2 and nothing else, and its executable is resolved in the caller before `chdir`.
      #
      # A cgroup that has been killed accepts no further children: every later clone3 into it is killed at once
      # (measured on kernels 6.8, 7.0 and 6.18), so `spawn` raises `Error::Killed`; create a new cgroup instead.
      def spawn(command : String, args : Enumerable(String) = [] of String, *,
                env : ::Process::Env = nil, clear_env : Bool = false,
                chdir : Path | String? = nil,
                input : ::Process::Stdio = ::Process::Redirect::Inherit,
                output : ::Process::Stdio = ::Process::Redirect::Inherit,
                error : ::Process::Stdio = ::Process::Redirect::Inherit,
                options : ProcessSupervision::SpawnOptions = ProcessSupervision::SpawnOptions.new) : ProcessSupervision::Child
        run_spawn("process-supervision-cgroup-spawn", options) do
          options.check_supported!("Linux cgroup v2", credentials: true, umask: true, rlimits: true, parent_death_signal: true,
            no_new_privileges: true, namespaces: true)
          prepared = ProcessSupervision::POSIX::Spawn.prepare(command, args, env, clear_env, chdir, nil, options)
          plumbing = ProcessSupervision::POSIX::Spawn::Plumbing.build(input, output, error, options, prepared.ipc_target)
          pending = begin
            @mutex.synchronize do
              check_open_locked
              if @killed
                raise ProcessSupervision::Error::Killed.new("cgroup #{@path} was killed and cannot take new children")
              end
              ProcessSupervision::Linux::RawSpawn.create(prepared, plumbing, cgroup: @path)
            end
          rescue ex
            plumbing.abandon
            raise ex
          end
          ProcessSupervision::Linux::RawSpawn.complete(pending, prepared, plumbing, self)
        end
      end

      def empty? : Bool
        @mutex.synchronize do
          check_open_locked
          !read_populated(@path / "cgroup.events")
        end
      end

      def wait_empty(timeout : Time::Span? = nil) : Bool
        run_on_execution_context("process-supervision-cgroup-wait-empty") do
          wait_empty_on_execution_context(timeout)
        end
      end

      def terminate : Nil
        raise ProcessSupervision::Error::Unsupported.new(
          "cgroup v2 has no atomic cooperative tree-termination primitive"
        )
      end

      def kill : Nil
        @mutex.synchronize do
          check_open_locked
          CgroupV2.raw_write(@path / "cgroup.kill", "1\n")
          @killed = true
        end
      rescue ex : File::AccessDeniedError
        raise ProcessSupervision::Error::Unavailable.new("cgroup.kill is not writable: #{ex.message}")
      rescue ex : File::Error
        raise ProcessSupervision::Error::Native.new("write(cgroup.kill)", ex.message || "cgroup kill failed")
      end

      def close : Nil
        @mutex.synchronize do
          return if @closed

          if @owned
            if read_populated(@path / "cgroup.events")
              raise ProcessSupervision::Error::Busy.new("cannot remove a populated cgroup")
            end
            if LibC.rmdir(@path.to_s) != 0
              raise File::Error.from_errno("Unable to remove directory", file: @path.to_s)
            end
          end

          @closed = true
        end
      rescue ex : ProcessSupervision::Error
        raise ex
      rescue ex : File::Error
        raise ProcessSupervision::Error::Native.new("rmdir(cgroup)", ex.message || "cgroup removal failed")
      end

      def closed? : Bool
        @mutex.synchronize { @closed }
      end

      private IN_MODIFY   = 0x00000002_u32
      private IN_NONBLOCK =         0o4000
      private IN_CLOEXEC  =      0o2000000

      # Event-driven: the kernel signals a modification of `cgroup.events` (inotify IN_MODIFY) when `populated` changes,
      # so this sleeps until then instead of polling. Falls back to polling if inotify is unavailable.
      private def wait_empty_on_execution_context(timeout : Time::Span?) : Bool
        validate_timeout(timeout)
        return true if empty?
        fd = LibProcessSupervisionInotify.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        return ProcessSupervision::Readiness.poll(timeout) { empty? } if fd < 0
        # handle: skips the constructor's blocking-mode setup, which would clear O_NONBLOCK on an anonymous-inode
        # descriptor (it treats anything that is not a pipe, socket or terminal as a blocking file) and turn the
        # drain loop below into a read that never returns.
        io = IO::FileDescriptor.new(handle: fd)
        begin
          if LibProcessSupervisionInotify.inotify_add_watch(fd, (@path / "cgroup.events").to_s, IN_MODIFY) < 0
            return ProcessSupervision::Readiness.poll(timeout) { empty? }
          end
          deadline = timeout.try { |span| Time.instant + span }
          buffer = Bytes.new(4096)
          loop do
            return true if empty?
            remaining = deadline.try { |limit| limit - Time.instant }
            return false if remaining && remaining <= Time::Span.zero
            return empty? unless ProcessSupervision::Readiness.wait_readable(io, remaining)
            # drain the queued events; the next empty? reads the current state
            while LibC.read(fd, buffer.to_unsafe, buffer.size) > 0
            end
          end
        ensure
          io.close rescue nil
        end
      end

      private def check_open_locked : Nil
        raise ProcessSupervision::Error::Closed.new("cgroup controller is closed") if @closed
      end

      private def self.mount_entries : Array(Tuple(Path, String))
        entries = [] of Tuple(Path, String)
        File.each_line("/proc/self/mountinfo") do |line|
          left, separator, right = line.partition(" - ")
          next if separator.empty?
          next unless right.starts_with?("cgroup2 ")
          fields = left.split
          next unless encoded_root = fields[3]?
          next unless encoded_mount = fields[4]?
          entries << {Path[decode_mount_field(encoded_mount)], decode_mount_field(encoded_root)}
        end
        entries
      rescue File::Error
        [] of Tuple(Path, String)
      end

      private def self.current_cgroup_path : String?
        File.each_line("/proc/self/cgroup") do |line|
          hierarchy, controllers, path = line.rstrip.split(':', 3)
          return path if hierarchy == "0" && controllers.empty?
        end
        nil
      rescue File::Error
        nil
      end

      # The initial cgroup namespace has a fixed inode (PROC_CGROUP_INIT_INO). Unreadable means unknown: assume initial,
      # which is the conservative answer for "is this mount root the machine's root".
      private def self.initial_cgroup_namespace? : Bool
        File.readlink("/proc/self/ns/cgroup") == "cgroup:[4026531835]"
      rescue File::Error
        true
      end

      private def self.active_mount_entry : Tuple(Path, String)?
        path = current_cgroup_path
        path ? best_mount_entry(path) : nil
      end

      private def self.best_mount_entry(cgroup_path : String) : Tuple(Path, String)?
        mount_entries
          .select { |(_, root)| !relative_to_mount_root(cgroup_path, root).nil? }
          .max_by? { |(_, root)| root.size }
      end

      private def self.relative_to_mount_root(cgroup_path : String, root : String) : String?
        return cgroup_path.lchop('/') if root == "/"
        return "" if cgroup_path == root
        return cgroup_path[root.size..].lchop('/') if cgroup_path.starts_with?("#{root}/")
        nil
      end

      private def self.mount_entry_for(path : String) : Tuple(Path, String)?
        mount_entries
          .select do |(mount, _)|
            begin
              within_mount?(path, File.realpath(mount))
            rescue File::Error
              false
            end
          end
          .max_by? { |(mount, _)| mount.to_s.size }
      end

      private def self.validate_interface!(path : String) : Nil
        %w[cgroup.procs cgroup.events cgroup.kill].each do |name|
          file = Path[path] / name
          unless File.file?(file)
            raise ProcessSupervision::Error::Unavailable.new("#{path} does not expose #{name}")
          end
        end
      end

      private def self.validate_name!(name : String) : Nil
        if name.empty? || name == "." || name == ".." || name.includes?('/') || name.includes?('\0')
          raise ArgumentError.new("cgroup name must be one non-empty path component")
        end
      end

      private def self.within_mount?(path : String, mount : String) : Bool
        path == mount || path.starts_with?(mount.ends_with?('/') ? mount : "#{mount}/")
      end

      private def self.decode_mount_field(value : String) : String
        value.gsub(/\\(040|011|012|134)/) do |match|
          case match[1]
          when "040" then " "
          when "011" then "\t"
          when "012" then "\n"
          else            "\\"
          end
        end
      end

      # Raw system calls for the interface files touched under @mutex: Crystal's File I/O may hand the thread off during
      # a blocking syscall (execution contexts), and a Thread::Mutex must be unlocked by the thread that locked it.
      protected def self.raw_write(path : Path, data : String) : Nil
        fd = LibC.open(path.to_s, LibC::O_WRONLY | LibC::O_CLOEXEC)
        raise File::Error.from_errno("Unable to open", file: path.to_s) if fd < 0
        begin
          if LibC.write(fd, data.to_unsafe, data.bytesize) < 0
            raise File::Error.from_errno("Unable to write", file: path.to_s)
          end
        ensure
          LibC.close(fd)
        end
      end

      protected def self.raw_read(path : Path) : String
        fd = LibC.open(path.to_s, LibC::O_RDONLY | LibC::O_CLOEXEC)
        raise File::Error.from_errno("Unable to open", file: path.to_s) if fd < 0
        begin
          buffer = Bytes.new(4096)
          count = LibC.read(fd, buffer.to_unsafe, buffer.size)
          raise File::Error.from_errno("Unable to read", file: path.to_s) if count < 0
          String.new(buffer[0, count])
        ensure
          LibC.close(fd)
        end
      end

      private def read_populated(events : Path) : Bool
        CgroupV2.raw_read(events).each_line do |line|
          fields = line.split(' ', 2)
          next unless fields.size == 2
          key, value = fields
          return value == "1" if key == "populated"
        end
        raise ProcessSupervision::Error::Native.new("read(cgroup.events)", "missing populated field")
      end
    end
  end
{% end %}
