require "spec"
require "../src/process-supervision"

# PROCESS_SUPERVISION_SPEC_ENGINE=fork|clone3 runs the whole suite on one Linux spawn engine (the default picks
# pidfd_spawn where the C library has it); shard-dev runs the suite once per engine.
{% if flag?(:linux) %}
  case ENV["PROCESS_SUPERVISION_SPEC_ENGINE"]?
  when "fork"   then ProcessSupervision::Linux::RawSpawn.clone3_disabled = true
  when "clone3" then ProcessSupervision::Linux::RawSpawn.pidfd_spawn_disabled = true
  end
{% end %}
