# What does Crystal's stdlib Process do on Windows? (crystal_spawn.cr covers POSIX.) JSON lines; never asserts.
# Questions: which handles a child inherits; what Process#terminate does and how its status reads; how exit codes
# map to Process::Status; spawn errors; executable search order (current directory vs PATH, chdir:); argument
# quoting; environment. Build: crystal build explore/windows/crystal_spawn_win.cr -o crystal_spawn_win.exe
require "json"
require "file_utils"

lib LibProbeWin
  struct SecurityAttributes
    nLength : UInt32
    lpSecurityDescriptor : Void*
    bInheritHandle : Int32
  end

  fun CreateEventW(sa : SecurityAttributes*, manual : Int32, initial : Int32, name : UInt16*) : Void*
  fun WaitForSingleObject(h : Void*, ms : UInt32) : UInt32
  fun GetHandleInformation(h : Void*, flags : UInt32*) : Int32
  fun ExitProcess(code : UInt32) : NoReturn
  fun GetCurrentProcessId : UInt32
  fun SetCurrentDirectoryW(path : UInt16*) : Int32
end

PROBE = "crystal_spawn_win"

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

def status_fields(j, status : Process::Status)
  j.field "to_s", status.to_s
  j.field "exit_code", status.exit_code?
  j.field "exit_reason", status.exit_reason.to_s
  j.field "normal_exit", status.normal_exit?
  j.field "signal_exit", status.signal_exit?
  j.field "success", status.success?
end

def failure(j, &)
  yield
  j.field "outcome", "spawned"
rescue ex
  j.field "outcome", "raised"
  j.field "exception", ex.class.name
  j.field "is_File_NotFoundError", ex.is_a?(File::NotFoundError)
  j.field "is_File_AccessDeniedError", ex.is_a?(File::AccessDeniedError)
  j.field "is_File_BadExecutableError", ex.is_a?(File::BadExecutableError)
  j.field "is_File_Error", ex.is_a?(File::Error)
  j.field "message", ex.message
  j.field "os_error", ex.as?(IO::Error).try(&.os_error).try { |e| "#{e} (#{e.value})" }
end

# ---- child modes -------------------------------------------------------------------------------------------------
case ARGV[0]?
when "--argv-json"
  puts ARGV[1..].to_json
  exit 0
when "--check-handle"
  h = Pointer(Void).new(ARGV[1].to_u64)
  flags = 0_u32
  valid = LibProbeWin.GetHandleInformation(h, pointerof(flags)) != 0
  signaled = valid && LibProbeWin.WaitForSingleObject(h, 0) == 0
  puts({valid: valid, signaled_event: signaled}.to_json)
  exit 0
when "--exit"
  LibProbeWin.ExitProcess(ARGV[1].to_u32(prefix: true))
when "--sleep"
  sleep 30.seconds
  exit 0
when "--marker"
  puts "copy-of-probe ran from #{Process.executable_path}"
  exit 0
when "--env"
  puts ENV.to_h.select { |k, _| k.upcase.in?("PATH", "PROBE_A", "PROBE_B", "SYSTEMROOT") }.to_json
  exit 0
end

self_exe = Process.executable_path.not_nil!

emit("_platform") do |j|
  j.field "crystal", Crystal::VERSION
  j.field "pid", LibProbeWin.GetCurrentProcessId
end

# ---- handle inheritance -------------------------------------------------------------------------------------------
emit("inheritable_handle_reaches_child") do |j|
  sa = LibProbeWin::SecurityAttributes.new(nLength: sizeof(LibProbeWin::SecurityAttributes), lpSecurityDescriptor: Pointer(Void).null, bInheritHandle: 1)
  inheritable = LibProbeWin.CreateEventW(pointerof(sa), 1, 1, Pointer(UInt16).null)
  private_ev = LibProbeWin.CreateEventW(Pointer(LibProbeWin::SecurityAttributes).null, 1, 1, Pointer(UInt16).null)
  [{"inheritable", inheritable}, {"not_inheritable", private_ev}].each do |name, h|
    io = IO::Memory.new
    Process.run(self_exe, ["--check-handle", h.address.to_s], output: io)
    j.field "#{name}_event_in_child", (JSON.parse(io.to_s) rescue io.to_s)
  end
end

# ---- terminate and status ---------------------------------------------------------------------------------------
emit("terminate_vs_exit_1") do |j|
  p = Process.new(self_exe, ["--sleep"])
  sleep 300.milliseconds
  p.terminate
  st = p.wait
  j.field "terminate" { j.object { status_fields(j, st) } }
  p2 = Process.new(self_exe, ["--sleep"])
  sleep 300.milliseconds
  p2.terminate(graceful: false)
  st2 = p2.wait
  j.field "terminate_graceful_false" { j.object { status_fields(j, st2) } }
  st3 = Process.run(self_exe, ["--exit", "1"])
  j.field "exit_1" { j.object { status_fields(j, st3) } }
  j.field "indistinguishable", st.exit_code? == st3.exit_code? && st.exit_reason == st3.exit_reason
end

emit("signal_on_windows") do |j|
  p = Process.new(self_exe, ["--sleep"])
  begin
    p.signal(Signal::TERM)
    j.field "signal_TERM", "ok"
  rescue ex
    j.field "signal_TERM", "#{ex.class}: #{ex.message}"
  end
  p.terminate rescue nil
  p.wait
end

{0, 1, 259, 0xC0000005, 0xC000013A, 0xC0000409, 0x40010004, 0xC0000094, 0xC00000FD, 0xE0000001}.each do |code|
  emit("status_exit_code_0x#{code.to_s(16)}") do |j|
    st = Process.run(self_exe, ["--exit", "0x#{code.to_s(16)}"])
    status_fields(j, st)
  end
end

# ---- spawn failures ---------------------------------------------------------------------------------------------
dir = File.join(Dir.tempdir, "crystal-spawn-win-#{Process.pid}")
Dir.mkdir_p(dir)
File.write(File.join(dir, "garbage.exe"), "this is not a PE file")
File.write(File.join(dir, "script.bat"), "@echo off\r\necho bat ran\r\n")
File.write(File.join(dir, "script.cmd"), "@echo off\r\necho cmd ran\r\n")
File.write(File.join(dir, "notes.txt"), "text")
{
  {"missing_file", File.join(dir, "missing.exe")},
  {"missing_bare_name", "no-such-program-for-probe"},
  {"directory", dir},
  {"garbage_exe", File.join(dir, "garbage.exe")},
  {"bat_file", File.join(dir, "script.bat")},
  {"cmd_file", File.join(dir, "script.cmd")},
  {"bat_file_with_trailing_dot_and_space", File.join(dir, "script.bat. ")},
  {"text_file", File.join(dir, "notes.txt")},
}.each do |name, cmd|
  emit("failed_spawn_#{name}") do |j|
    failure(j) { Process.run(cmd, output: Process::Redirect::Close, error: Process::Redirect::Close) }
  end
end
emit("chdir_missing") do |j|
  failure(j) { Process.run(self_exe, ["--exit", "0"], chdir: File.join(dir, "nope")) }
end

# ---- executable search order: a copy named like a system tool in the current directory -----------------------------
emit("search_order_current_directory_vs_path") do |j|
  hijack_dir = File.join(dir, "cwd")
  Dir.mkdir_p(hijack_dir)
  File.copy(self_exe, File.join(hijack_dir, "whoami.exe"))
  original = Dir.current
  Dir.cd(hijack_dir)
  io = IO::Memory.new
  st = Process.run("whoami", ["--marker"], output: io, error: Process::Redirect::Close) rescue nil
  j.field "bare_whoami_ran", io.to_s.includes?("copy-of-probe") ? "copy in the current directory" : "system whoami (or other)"
  j.field "output_head", io.to_s[0, 120]
  Dir.cd(original)
  io2 = IO::Memory.new
  Process.run("whoami", ["--marker"], output: io2, error: Process::Redirect::Close, chdir: hijack_dir) rescue nil
  j.field "with_chdir_option_ran", io2.to_s.includes?("copy-of-probe") ? "copy in the chdir directory" : "system whoami (or other)"
  io3 = IO::Memory.new
  rel = File.join("cwd", "whoami.exe")
  Dir.cd(dir)
  res = begin
    Process.run(rel, ["--marker"], output: io3, chdir: hijack_dir)
    io3.to_s.includes?("copy-of-probe") ? "ran (resolved against the parent's directory)" : "ran something else"
  rescue ex
    "#{ex.class}: #{ex.message}"
  end
  Dir.cd(original)
  j.field "relative_path_with_chdir", res
end

# ---- argument quoting -------------------------------------------------------------------------------------------
emit("argument_round_trip") do |j|
  args = ["a b", %("quoted"), %(back\\slash\\), %(trail\\), "", "%PATH%", "^&|<>", %(a\\"b), "tab\there", "ünïcödé", "two  spaces"]
  io = IO::Memory.new
  Process.run(self_exe, ["--argv-json"] + args, output: io)
  got = Array(String).from_json(io.to_s) rescue [] of String
  j.field "all_equal", got == args
  j.field "mismatches" do
    j.array { args.each_with_index { |a, i| j.string("#{a.inspect} -> #{got[i]?.inspect}") unless got[i]? == a } }
  end
end

# ---- environment ------------------------------------------------------------------------------------------------
emit("environment") do |j|
  io = IO::Memory.new
  Process.run(self_exe, ["--env"], output: io, env: {"PROBE_A" => "1", "probe_a" => "2"})
  j.field "PROBE_A_and_probe_a_given", (JSON.parse(io.to_s) rescue io.to_s)
  io2 = IO::Memory.new
  st = Process.run(self_exe, ["--env"], output: io2, clear_env: true, env: {"PROBE_B" => "x"}) rescue nil
  j.field "clear_env_child_ran", !st.nil?
  j.field "clear_env_child_sees", (JSON.parse(io2.to_s) rescue io2.to_s)
end

FileUtils.rm_rf(dir) rescue nil
