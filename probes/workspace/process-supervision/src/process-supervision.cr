require "process-handle"
# Not on Windows: requiring the socket library starts Winsock at program start, and WSAStartup fails in a process
# whose environment lacks SystemRoot (a child spawned with clear_env), killing it before main.
{% unless flag?(:win32) %}
  require "socket"
{% end %}
require "./process-supervision/version"
require "./process-supervision/error"
require "./process-supervision/mechanism"
require "./process-supervision/execution_bridge"
require "./process-supervision/stream_copies"
require "./process-supervision/readiness"
require "./process-supervision/spawn_options"
require "./process-supervision/exit_outcome"
require "./process-supervision/lifeline"
require "./process-supervision/group"
require "./process-supervision/child"
require "./process-supervision/supervisor"

{% if flag?(:unix) %}
  require "./process-supervision/posix/spawn"
  require "./process-supervision/posix/marker_scan"
  require "./process-supervision/posix/process_group"
{% end %}

{% if flag?(:darwin) %}
  require "./process-supervision/posix/darwin_spawn"
{% end %}

{% if flag?(:linux) %}
  require "./process-supervision/linux/raw_spawn"
  require "./process-supervision/linux/cgroup_v2"
  require "./process-supervision/linux/cgroup_control"
{% end %}

{% if flag?(:win32) %}
  require "./process-supervision/windows/native"
  require "./process-supervision/windows/job/base"
  require "./process-supervision/windows/job/limits"
  require "./process-supervision/windows/job/accounting"
  require "./process-supervision/windows/job/limit_events"
  require "./process-supervision/windows/job"
  require "./process-supervision/windows/spawn"
  require "./process-supervision/windows/job_control"
{% end %}

module ProcessSupervision
  {% if flag?(:unix) %}
    def self.process_group(pgid : Int) : Group
      POSIX::ProcessGroup.new(pgid.to_i64)
    end
  {% end %}

  {% if flag?(:linux) %}
    def self.cgroup_v2(path : Path | String, *, fallback_pgid : Int? = nil) : Group
      Linux::CgroupV2.open(path)
    rescue ex : Error::Unavailable
      raise ex unless fallback_pgid
      POSIX::ProcessGroup.new(fallback_pgid.to_i64)
    end
  {% end %}

  {% if flag?(:win32) %}
    def self.job(limits : Windows::Job::Limits? = nil) : Windows::Job
      Windows::Job.new(limits)
    end
  {% end %}

  # The strongest mechanism `spawn` can use on this host right now. Detection is by trying, not by reading mounts: on
  # Linux a cgroup is used only where this process can actually create one (a service manager delegated a subtree, a
  # user manager's unit, a privileged container), which probing a throwaway child cgroup tells.
  def self.strongest_mechanism : Mechanism
    {% if flag?(:win32) %}
      Mechanism::JobObject
    {% elsif flag?(:linux) %}
      Linux::CgroupV2.delegated_parent ? Mechanism::CgroupV2 : Mechanism::ProcessGroup
    {% else %}
      Mechanism::ProcessGroup
    {% end %}
  end

  # Spawns a direct executable/argv child under the strongest containment this host offers and returns it;
  # `child.group.mechanism` says which one it got: a Job Object on Windows, a fresh cgroup on Linux where one can be
  # created (the child and every descendant are inside it before they run), otherwise a new process group (a weaker
  # container: a descendant can leave it with setsid). The caller owns the group: `child.group.shutdown` ends the tree
  # and releases the group; closing the child does neither.
  def self.spawn(command : String, args : Enumerable(String) = [] of String, *,
                 env : ::Process::Env = nil, clear_env : Bool = false,
                 chdir : Path | String? = nil,
                 input : ::Process::Stdio = ::Process::Redirect::Inherit,
                 output : ::Process::Stdio = ::Process::Redirect::Inherit,
                 error : ::Process::Stdio = ::Process::Redirect::Inherit,
                 options : SpawnOptions = SpawnOptions.new) : Child
    {% if flag?(:win32) %}
      job = Windows::Job.new
      begin
        job.spawn(command, args, env: env, clear_env: clear_env, chdir: chdir, input: input, output: output, error: error, options: options)
      rescue ex
        job.close rescue nil
        raise ex
      end
    {% elsif flag?(:linux) %}
      if parent = Linux::CgroupV2.delegated_parent
        group = begin
          Linux::CgroupV2.create(parent, "process-supervision-#{::Process.pid}-#{Random.new.hex(4)}")
        rescue Error::Unavailable
          nil
        end
        if group
          begin
            return group.spawn(command, args, env: env, clear_env: clear_env, chdir: chdir, input: input, output: output, error: error, options: options)
          rescue ex : Error::Unavailable
            # lost the delegation between the probe and the spawn: use the weaker mechanism rather than fail
            group.close rescue nil
          rescue ex
            group.close rescue nil
            raise ex
          end
        end
      end
      POSIX::ProcessGroup.spawn_leader(command, args, env: env, clear_env: clear_env, chdir: chdir, input: input, output: output, error: error, options: options)
    {% elsif flag?(:unix) %}
      POSIX::ProcessGroup.spawn_leader(command, args, env: env, clear_env: clear_env, chdir: chdir, input: input, output: output, error: error, options: options)
    {% else %}
      raise Error::Unsupported.new("spawning is not implemented for this target")
    {% end %}
  end
end
