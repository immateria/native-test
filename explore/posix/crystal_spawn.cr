# What does Crystal's stdlib Process.new actually do on POSIX? The kit's macOS shard has no spawn path of its
# own, so its 128 macOS spawn_* cases exercise this. Records: what a child inherits (signal mask, ignored
# signals, plain descriptors), pgroup:/chdir:, and which exception class and message each failed spawn gives.
#
# Build: crystal build explore/posix/crystal_spawn.cr -o crystal_spawn
# Run:   ./crystal_spawn <path to the sigstate binary built from sigstate.c>
require "json"
require "file_utils"

PROBE = "crystal_spawn"

lib LibProbe
  fun setpgid(pid : Int32, pgid : Int32) : Int32
  fun getpgid(pid : Int32) : Int32
end

def emit(kase : String, &)
  line = JSON.build do |j|
    j.object do
      j.field "probe", PROBE
      j.field "case", kase
      begin
        yield j
      rescue ex
        # record and carry on: one surprising case must not hide the rest
        j.field "unhandled_error", "#{ex.class}: #{ex.message}"
      end
    end
  end
  puts line
  STDOUT.flush
end

def dump_json(text : String) : JSON::Any
  JSON.parse(text.lines.first? || "null")
rescue
  JSON::Any.new(text)
end

sigstate = ARGV[0]? || abort("usage: crystal_spawn <sigstate binary>")

emit("_platform") do |j|
  j.field "crystal", Crystal::VERSION
  j.field "target", Crystal::DESCRIPTION.lines.first? || ""
end

# --- inheritance -----------------------------------------------------------------------------------------
Signal::INT.ignore
Signal::HUP.ignore
Signal::USR2.trap { }
mask_rc = -1
plain_fd = -1
{% if flag?(:unix) %}
  set = uninitialized LibC::SigsetT
  LibC.sigemptyset(pointerof(set))
  LibC.sigaddset(pointerof(set), Signal::USR1.value)
  LibC.sigaddset(pointerof(set), Signal::TERM.value)
  mask_rc = LibC.pthread_sigmask({% if flag?(:darwin) %}1{% else %}0{% end %}, pointerof(set), nil) # SIG_BLOCK
  plain_fd = LibC.open("/dev/null", LibC::O_RDONLY)
{% end %}

def run_dump(sigstate : String, chdir : String? = nil) : {Process::Status, String}
  io = IO::Memory.new
  status = Process.run(sigstate, ["--dump"], output: io, error: Process::Redirect::Close, chdir: chdir)
  {status, io.to_s}
end

emit("crystal_process_run_inherits") do |j|
  j.field "parent_state", "ignore INT,HUP; trap USR2; pthread_sigmask(block USR1,TERM) rc=#{mask_rc} on the spawning thread; plain fd #{plain_fd} opened without CLOEXEC"
  status, text = run_dump(sigstate)
  j.field "status", status.to_s
  j.field "child_dump", dump_json(text)
end

# Crystal's Process.run/new have no pgroup: option (see the overload list the compiler prints), so a group
# for the child can only be made by the parent calling setpgid(child, child) after the spawn. Process.new
# returns only after the child's exec succeeded, so measure what that call then reports.
emit("setpgid_by_parent_after_Process_new") do |j|
  ok = 0
  eacces = 0
  esrch = 0
  other = 0
  alone = 0
  trials = 100
  trials.times do
    pr = Process.new("/bin/sh", ["-c", "sleep 0.3"])
    rc = LibProbe.setpgid(pr.pid, pr.pid)
    if rc == 0
      ok += 1
      alone += 1 if LibProbe.getpgid(pr.pid) == pr.pid
    elsif Errno.value == Errno::EACCES
      eacces += 1
    elsif Errno.value == Errno::ESRCH
      esrch += 1
    else
      other += 1
    end
    pr.terminate
    pr.wait
  end
  j.field "trials", trials
  j.field "setpgid_ok", ok
  j.field "setpgid_EACCES_child_already_exec_ed", eacces
  j.field "setpgid_ESRCH", esrch
  j.field "setpgid_other", other
  j.field "child_is_own_group_leader_afterwards", alone
end

# The first CI run passed a relative path (explore-out/build/sigstate) and chdir: "/tmp" failed with
# File::NotFoundError: the command path is resolved after the child has changed directory.
relative = sigstate
absolute = File.expand_path(sigstate)
emit("relative_command_path_with_chdir") do |j|
  j.field "command", relative
  j.field "command_is_relative", !relative.starts_with?('/')
  j.field "relative_from_new_dir_exists", File.exists?(File.join("/tmp", relative))
  begin
    status, _ = run_dump(relative, chdir: "/tmp")
    j.field "outcome", "spawned"
    j.field "status", status.to_s
  rescue ex
    j.field "outcome", "raised"
    j.field "exception", ex.class.name
    j.field "message", ex.message
  end
end
sigstate = absolute

emit("chdir_tmp") do |j|
  status, text = run_dump(sigstate, chdir: "/tmp")
  j.field "status", status.to_s
  j.field "child_dump", dump_json(text)
end

emit("chdir_missing") do |j|
  begin
    status, text = run_dump(sigstate, chdir: "/nonexistent-dir-for-probe")
    j.field "outcome", "spawned"
    j.field "status", status.to_s
  rescue ex
    j.field "exception", ex.class.name
    j.field "message", ex.message
    j.field "os_error", ex.as?(IO::Error).try(&.os_error.try(&.to_s)) || ""
  end
end

# --- failures --------------------------------------------------------------------------------------------
dir = File.join(Dir.tempdir, "crystal-spawn-#{Process.pid}")
Dir.mkdir_p(dir)
def write(dir, name, content, mode)
  path = File.join(dir, name)
  File.write(path, content)
  File.chmod(path, mode)
  path
end

noexec = write(dir, "not_executable", "#!/bin/sh\nexit 0\n", 0o644)
noshebang = write(dir, "no_shebang", "exit 0\n", 0o755)
badinterp = write(dir, "bad_interpreter", "#!/nonexistent/interpreter\n", 0o755)
garbage = write(dir, "garbage", Bytes.new(128) { |i| (0x80 + i).to_u8 }.to_a.map(&.chr).join, 0o755)
loop_path = File.join(dir, "loop")
File.symlink("loop", loop_path)

cases = [
  {"missing_file", File.join(dir, "missing"), [] of String},
  {"missing_bare_name_path_search", "no-such-program-for-probe", [] of String},
  {"directory", dir, [] of String},
  {"no_exec_permission", noexec, [] of String},
  {"script_without_shebang", noshebang, [] of String},
  {"script_with_missing_interpreter", badinterp, [] of String},
  {"garbage_bytes_executable", garbage, [] of String},
  {"symlink_loop", loop_path, [] of String},
  {"path_longer_than_PATH_MAX", "a" * 5000, [] of String},
  {"argv_over_ARG_MAX", sigstate, ["--dump"] + Array.new(100) { "x" * 100_000 }}, # 10 MB: above ARG_MAX everywhere (Linux: stack limit / 4)
  {"component_is_a_file", File.join(noexec, "child"), [] of String},
]
cases.each do |(name, cmd, args)|
  emit("failed_spawn_#{name}") do |j|
    begin
      status = Process.run(cmd, args, output: Process::Redirect::Close, error: Process::Redirect::Close)
      j.field "outcome", "spawned"
      j.field "status", status.to_s
      j.field "exit_code", status.exit_code
    rescue ex
      j.field "exception", ex.class.name
      j.field "is_File_NotFoundError", ex.is_a?(File::NotFoundError)
      j.field "is_File_AccessDeniedError", ex.is_a?(File::AccessDeniedError)
      j.field "is_File_Error", ex.is_a?(File::Error)
      j.field "is_IO_Error", ex.is_a?(IO::Error)
      j.field "message", ex.message
      j.field "os_error", ex.as?(IO::Error).try(&.os_error.try(&.to_s)) || ""
    end
  end
end

# --- exit statuses ---------------------------------------------------------------------------------------
{ {"sigterm", "kill -TERM $$"}, {"sigkill", "kill -KILL $$"}, {"exit_7", "exit 7"}, {"sigsegv", "kill -SEGV $$"} }.each do |(name, script)|
  emit("status_#{name}") do |j|
    status = Process.run("/bin/sh", ["-c", script])
    j.field "to_s", status.to_s
    j.field "normal_exit", status.normal_exit?
    j.field "signal_exit", status.signal_exit?
    j.field "exit_signal", status.exit_signal?.try(&.to_s) || ""
    j.field "exit_reason", status.exit_reason.to_s
    j.field "success", status.success?
  end
end

# a stopped child: does Process#terminate (SIGTERM) finish it?
emit("terminate_stopped_child") do |j|
  p = Process.new("/bin/sh", ["-c", "sleep 30"])
  sleep 100.milliseconds
  p.signal(Signal::STOP)
  sleep 100.milliseconds
  p.terminate
  sleep 400.milliseconds
  j.field "terminated_after_400ms_with_SIGTERM_only", p.terminated?
  p.signal(Signal::CONT)
  sleep 300.milliseconds
  j.field "terminated_after_SIGCONT", p.terminated?
  p.signal(Signal::KILL) unless p.terminated?
  st = p.wait
  j.field "final_status", st.to_s
end

FileUtils.rm_rf(dir)
