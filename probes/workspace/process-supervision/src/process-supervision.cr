require "process-handle"
require "./process-supervision/version"
require "./process-supervision/error"
require "./process-supervision/mechanism"
require "./process-supervision/execution_bridge"
require "./process-supervision/group"
require "./process-supervision/child"

{% if flag?(:unix) %}
  require "./process-supervision/posix/spawn"
  require "./process-supervision/posix/process_group"
{% end %}

{% if flag?(:darwin) %}
  require "./process-supervision/posix/darwin_spawn"
{% end %}

{% if flag?(:linux) %}
  require "./process-supervision/linux/raw_spawn"
  require "./process-supervision/linux/cgroup_v2"
{% end %}

{% if flag?(:win32) %}
  require "./process-supervision/windows/native"
  require "./process-supervision/windows/job/base"
  require "./process-supervision/windows/job/limits"
  require "./process-supervision/windows/job/accounting"
  require "./process-supervision/windows/job/limit_events"
  require "./process-supervision/windows/job"
  require "./process-supervision/windows/spawn"
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
end
