# Exercises the kit's Linux code paths that its specs do not reach: ProcessSupervision::Linux::CgroupV2 on a real
# delegated cgroup (create, attach, kill a tree that left its process group and session, wait_empty, shutdown,
# close) and ProcessHandle::Linux (pidfd) on live, exited, reaped and foreign processes. JSON lines; never asserts.
#
# Run inside a delegated cgroup subtree:  kit_linux <delegated dir>
# Build: CRYSTAL_PATH=probes/workspace/process-supervision/src:probes/workspace/process-handle/src:$(crystal env CRYSTAL_PATH) \
#        crystal build explore/linux/kit_linux.cr -o kit_linux
require "json"
require "process-supervision"

PROBE = "kit_linux"

def emit(kase : String, &)
  line = JSON.build do |j|
    j.object do
      j.field "probe", PROBE
      j.field "case", kase
      begin
        yield j
      rescue ex
        j.field "unhandled_error", "#{ex.class}: #{ex.message}"
      end
    end
  end
  puts line
  STDOUT.flush
end

def outcome(& : -> _) : String
  yield
  "ok"
rescue ex
  "#{ex.class}: #{ex.message}"
end

def procs(path : Path) : Int32
  File.read(path / "cgroup.procs").lines.size
rescue
  -1
end

def alive?(pid : Int64) : Bool
  return false unless File.exists?("/proc/#{pid}/stat")
  state = File.read("/proc/#{pid}/stat").split(')').last.split[0]? || ""
  state != "Z"
rescue
  false
end

delegated = Path[ARGV[0]? || abort("usage: kit_linux <delegated cgroup dir>")]
CG = ProcessSupervision::Linux::CgroupV2

emit("discovery") do |j|
  j.field "available", CG.available?
  j.field "mountpoint", CG.mountpoint.to_s
  j.field "current_path", CG.current_path.to_s
  j.field "open_hierarchy_root", outcome { CG.open(CG.mountpoint.not_nil!) }
  j.field "create_under_hierarchy_root", outcome { CG.create(CG.mountpoint.not_nil!, "kit-linux-undelegated").close }
  j.field "create_bad_name", outcome { CG.create(delegated, "a/b") }
end

# a shell that, 0.3 s after it starts (i.e. after attach), daemonizes a sleeper into a new session
TREE = "sleep 0.3; setsid sh -c 'echo $$ > \"$0\"; exec sleep 60' \"$1\" & sleep 60"

def spawn_tree(marker : String) : Process
  Process.new("/bin/sh", ["-c", TREE, marker, marker])
end

emit("cgroup_kill_reaches_daemonized_descendant") do |j|
  group = CG.create(delegated, "kit-kill")
  marker = "/tmp/kit-linux-daemon-#{Process.pid}"
  process = spawn_tree(marker)
  j.field "attach", outcome { group.attach(process.pid) }
  sleep 700.milliseconds
  daemon = File.read(marker).strip.to_i64 rescue -1_i64
  j.field "procs_in_cgroup", procs(group.path)
  j.field "daemon_pid_known", daemon > 0
  j.field "daemon_in_other_session", daemon > 0 && File.read("/proc/#{daemon}/stat").split(')').last.split[3]? != File.read("/proc/#{process.pid}/stat").split(')').last.split[3]? # field 6, session
  j.field "empty_before", group.empty?
  j.field "close_while_populated", outcome { group.close }
  t0 = Time.instant
  j.field "kill", outcome { group.kill }
  drained = group.wait_empty(3.seconds)
  j.field "wait_empty", drained
  j.field "ms_to_empty", (Time.instant - t0).total_milliseconds.round(1)
  j.field "daemon_alive_after", daemon > 0 && alive?(daemon)
  status = process.wait
  j.field "shell_status", status.to_s
  j.field "close_after_empty", outcome { group.close }
  j.field "directory_removed", !Dir.exists?(group.path)
  File.delete?(marker)
end

emit("shutdown_policy_on_cgroup") do |j|
  group = CG.create(delegated, "kit-shutdown")
  process = Process.new("/bin/sh", ["-c", "trap '' TERM; sleep 60"])
  group.attach(process.pid)
  j.field "soft_termination", group.soft_termination?
  j.field "terminate", outcome { group.terminate }
  t0 = Time.instant
  result = group.shutdown(grace: 500.milliseconds, kill_after: 2.seconds)
  j.field "ms", (Time.instant - t0).total_milliseconds.round(1)
  j.field "terminate_requested", result.terminate_requested?
  j.field "kill_requested", result.kill_requested?
  j.field "drained", result.drained?
  j.field "closed", result.closed?
  j.field "status", process.wait.to_s
end

emit("attach_errors") do |j|
  group = CG.create(delegated, "kit-attach")
  j.field "attach_nonexistent_pid", outcome { group.attach(999_999_999) }
  j.field "attach_zero", outcome { group.attach(0) }
  group.close
  j.field "attach_after_close", outcome { group.attach(Process.pid) }
end

emit("open_existing_and_own_cgroup") do |j|
  own = CG.current_path.not_nil!
  g = CG.open(own)
  j.field "own_cgroup_open", true
  j.field "owned", g.owned
  j.field "own_cgroup_empty", g.empty? # false: we are in it; never kill this one
  j.field "close_unowned_keeps_directory", (g.close; Dir.exists?(own))
end

# --- ProcessHandle::Linux ---------------------------------------------------------------------------------------
emit("pidfd_handle_lifecycle") do |j|
  process = Process.new("/bin/sleep", ["30"])
  handle = ProcessHandle.open(process.pid)
  j.field "mechanism", handle.mechanism.to_s
  j.field "alive_initially", handle.alive?
  j.field "wait_100ms_on_live", handle.wait(100.milliseconds)
  j.field "terminate", outcome { handle.terminate }
  j.field "wait_after_terminate", handle.wait(2.seconds)
  j.field "alive_after", handle.alive?
  status = process.wait # the runtime has reaped it by now or reaps it here
  j.field "status", status.to_s
  j.field "kill_after_reap", outcome { handle.kill }
  j.field "terminate_after_reap", outcome { handle.terminate }
  j.field "alive_after_reap", handle.alive?
  j.field "lookup_identity_after_reap", ProcessHandle::Linux.lookup_identity(process.pid.to_i64).nil? ? "nil" : "present"
  j.field "open_after_reap", outcome { ProcessHandle.open(process.pid).close }
  handle.close
  j.field "alive_after_close", outcome { handle.alive? }
end

emit("pidfd_handle_on_foreign_processes") do |j|
  init = ProcessHandle.open(1)
  j.field "open_pid_1", true
  j.field "pid_1_alive", init.alive?
  init.close
  j.field "open_nonexistent", outcome { ProcessHandle.open(999_999_999).close }
end

emit("pidfd_handle_concurrent_waiters") do |j|
  process = Process.new("/bin/sleep", ["0.3"])
  handle = ProcessHandle.open(process.pid)
  results = Channel(Bool).new(8)
  8.times { spawn { results.send(handle.wait(3.seconds)) } }
  got = Array(Bool).new(8) { results.receive }
  j.field "waiters_that_saw_exit", got.count(&.itself)
  j.field "status", process.wait.to_s
  handle.close
end

emit("child_with_cgroup_group") do |j|
  group = CG.create(delegated, "kit-child")
  process = Process.new("/bin/sh", ["-c", "sleep 0.2; exit 4"])
  group.attach(process.pid)
  handle = ProcessHandle.open(process.pid)
  child = ProcessSupervision::Child.new(process, handle, group)
  status = child.wait(3.seconds)
  j.field "exit_code", status.try(&.exit_code) || -1
  j.field "group_empty_after", group.empty?
  j.field "close", outcome { child.close }
  # Child#close closes the process and the handle, not the group (by design: the group may be shared)
  j.field "cgroup_directory_left_after_child_close", Dir.exists?(group.path)
  j.field "group_close", outcome { group.close }
end
