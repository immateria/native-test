# Windows argument passing, measured instead of assumed (explore-hard.yml):
#
# 1. Process.quote_windows against CommandLineToArgvW, in process (many random argument lists);
# 2. the same through a real child: argdump.exe (cl.exe, Universal CRT parsing) and a Crystal child (this program);
# 3. batch files: which spellings of a .bat/.cmd path get past the "batch files are refused" checks of
#    Process.new and ProcessSupervision's Job#spawn, and whether an argument then injects a command;
# 4. a candidate quoting for cmd.exe (the scheme Rust adopted after "BatBadBut"), fuzzed through a wrapper .cmd that
#    passes %* to argdump.exe; any argument that does not round-trip, and any injected command, is reported.
#
# Output: JSON lines on stdout. Usage: argv_fuzz <argdump.exe> <work dir> [seed]
#         argv_fuzz --dump            (child mode: prints ARGV as UTF-16 hex lines)
require "json"
require "process-supervision"

@[Link("shell32")]
lib LibArgShell
  fun CommandLineToArgvW(cmd : UInt16*, argc : Int32*) : UInt16**
end

lib LibArgK32
  fun GetShortPathNameW(long : UInt16*, short : UInt16*, size : UInt32) : UInt32
end

def hex(s : String) : String
  s.to_utf16.map { |u| u.to_s(16).rjust(4, '0') }.join
end

def emit(kind : String, **fields)
  puts({"case" => kind}.merge(fields.to_h.transform_keys(&.to_s)).to_json)
  STDOUT.flush
end

if ARGV.first? == "--dump"
  ARGV[1..].each { |arg| puts hex(arg) }
  exit 0
end

argdump = ARGV[0]
work = Path[ARGV[1]].expand
seed = (ARGV[2]? || Random.new.rand(UInt32::MAX).to_s).to_u64
Dir.mkdir_p(work)
rng = Random.new(seed)
emit "context", seed: seed, crystal: Crystal::VERSION, argdump: argdump

ALPHABET = ["a", "b", "Z", "0", " ", " ", "\t", "\"", "\"", "\\", "\\", "\\\\", "^", "&", "|", "<", ">", "%", "%PATH%",
            "!", "(", ")", "'", "*", "?", "=", ";", ",", "@", "é", "€", "😀", "　", " ", "-", "/", ":"]
RARE = ["\n", "\r", "\v", "\f"]

def random_arg(rng, allow_rare = false) : String
  return "" if rng.rand(12) == 0
  String.build do |io|
    rng.rand(1..10).times do
      if allow_rare && rng.rand(40) == 0
        io << RARE.sample(rng)
      else
        io << ALPHABET.sample(rng)
      end
    end
  end
end

def random_args(rng, allow_rare = false) : Array(String)
  Array.new(rng.rand(1..5)) { random_arg(rng, allow_rare) }
end

def command_line_to_argv(line : String) : Array(String)
  argc = 0
  argv = LibArgShell.CommandLineToArgvW(line.to_utf16.to_unsafe, pointerof(argc))
  raise "CommandLineToArgvW failed" if argv.null?
  result = Array.new(argc) { |i| String.from_utf16(argv[i])[0] }
  LibC.LocalFree(argv.as(Void*))
  result
end

def report(kind, cases, failures, samples, **extra)
  emit kind, **extra.merge({cases: cases, mismatches: failures, samples: samples.first(8)})
end

# 1. in-process: quote_windows -> CommandLineToArgvW
begin
  failures = 0
  samples = [] of Hash(String, String)
  cases = 20_000
  cases.times do
    args = random_args(rng, allow_rare: true)
    line = Process.quote_windows(["prog.exe"] + args)
    back = command_line_to_argv(line)[1..]
    next if back == args
    failures += 1
    samples << {"args" => args.inspect, "line" => line, "back" => back.inspect}
  end
  report "quote_windows_vs_CommandLineToArgvW", cases, failures, samples
end

# 2. through real children
{ {"ucrt_argdump", argdump, [] of String, 1500}, {"crystal_child", Process.executable_path.not_nil!, ["--dump"], 300} }.each do |(kind, exe, prefix, cases)|
  failures = 0
  errors = 0
  samples = [] of Hash(String, String)
  started = Time.instant
  cases.times do
    args = random_args(rng, allow_rare: true)
    output = IO::Memory.new
    status = Process.run(exe, prefix + args, output: output, error: Process::Redirect::Close)
    unless status.success?
      errors += 1
      next
    end
    got = output.to_s.split('\n')[0...-1]
    expected = args.map { |a| hex(a) }
    next if got == expected
    failures += 1
    samples << {"args" => args.inspect, "line" => Process.quote_windows(args), "got_hex" => got.inspect}
  end
  report kind, cases, failures, samples, child_errors: errors, ms_per_child: ((Time.instant - started).total_milliseconds / cases).round(1)
end

# 3. batch-file spellings against the refusal checks
bat_body = "@echo off\r\necho ran %* > \"%~dp0ran.txt\"\r\n"
File.write(work / "t.bat", bat_body)
File.write(work / "t.cmd", bat_body)
File.write(work / "longbatchname.bat", bat_body)
File.write(work / "tonly.bat", bat_body)
File.write(work / "batch-text.exe", bat_body)
ads_results = {} of String => String
{"plain.txt:evil.bat", "t2.bat:s", "noext:s"}.each do |stream|
  begin
    File.write(work / "#{stream.split(':')[0]}", "x") unless File.exists?(work / stream.split(':')[0])
    File.write((work / stream).to_s, bat_body)
    ads_results[stream] = "written"
  rescue ex
    ads_results[stream] = "#{ex.class}: #{ex.message}"
  end
end
short = Bytes.new(0)
short_buffer = Slice(UInt16).new(1024)
long = (work / "longbatchname.bat").to_s
n = LibArgK32.GetShortPathNameW(long.to_utf16.to_unsafe, short_buffer.to_unsafe, 1024_u32)
short_name = n > 0 ? String.from_utf16(short_buffer[0, n]) : nil
emit "batch_setup", ads: ads_results, short_name: short_name

variants = ["t.bat", "T.BAT", "t.bat.", "t.bat ", "t.bat. . ", "t.bat::$DATA", "t.bat\t", "t.bat/", "t.bat\\",
            "t.cmd", "t.cmd::$DATA", "t", "batch-text.exe", "plain.txt:evil.bat", "t2.bat:s", "noext:s"]
full = variants.map { |v| (work.to_s + "\\" + v) }
full << short_name if short_name
full << "tonly"
ENV["PATH"] = "#{work};#{ENV["PATH"]?}"
payload = %("&echo injected>inj.txt&rem )
job = ProcessSupervision.job
full.each do |command|
  {"Process.new", "Job#spawn"}.each do |api|
    File.delete?(work / "ran.txt")
    File.delete?(work / "inj.txt")
    outcome = begin
      if api == "Process.new"
        st = Process.run(command, ["x", payload], chdir: work.to_s, output: Process::Redirect::Close, error: Process::Redirect::Close)
        "exit #{st.exit_code}"
      else
        child = job.spawn(command, ["x", payload], chdir: work.to_s, output: Process::Redirect::Close, error: Process::Redirect::Close)
        st = child.wait(10.seconds)
        child.close
        st ? "exit #{st.exit_code}" : "timeout"
      end
    rescue ex
      "#{ex.class}: #{ex.message}"
    end
    emit "batch_variant", api: api, command: command.sub(work.to_s, "<work>"), outcome: outcome,
      ran: File.exists?(work / "ran.txt"), injected: File.exists?(work / "inj.txt")
  end
end
job.close

# 4. candidate cmd.exe quoting (Rust's make_bat_command_line), through a wrapper .cmd into argdump.exe
def bat_arg(arg : String) : String
  quote = arg.empty? || arg.ends_with?('\\')
  arg.each_char do |c|
    if (c.ascii? && !(c.ascii_alphanumeric? || "#$*+-./:?@\\_".includes?(c))) || c.control?
      quote = true
    end
  end
  String.build do |io|
    io << '"' if quote
    backslashes = 0
    arg.each_char do |c|
      if c == '\\'
        backslashes += 1
      else
        if c == '"'
          io << "\\" * backslashes
          io << '"'
        elsif c == '%' || c == '\r'
          io << "%%cd:~,"
        end
        backslashes = 0
      end
      io << c
    end
    if quote
      io << "\\" * backslashes
      io << '"'
    end
  end
end

def raw_run(command_line : String, timeout_ms = 15_000_u32) : Int64
  startup = LibC::STARTUPINFOW.new
  startup.cb = sizeof(LibC::STARTUPINFOW).to_u32
  info = LibC::PROCESS_INFORMATION.new
  line = command_line.to_utf16
  buffer = Slice(UInt16).new(line.size + 1)
  line.copy_to(buffer)
  ok = LibC.CreateProcessW(Pointer(UInt16).null, buffer.to_unsafe, nil, nil, 0, 0x08000000_u32, nil, nil, pointerof(startup), pointerof(info))
  return -1_i64 if ok == 0
  LibC.WaitForSingleObject(info.hProcess, timeout_ms)
  code = 0_u32
  LibC.GetExitCodeProcess(info.hProcess, pointerof(code))
  LibC.CloseHandle(info.hProcess)
  LibC.CloseHandle(info.hThread)
  code.to_i64
end

wrapper = work / "w.cmd"
File.write(wrapper, "@\"%~dp0argdump.exe\" %*\r\n")
File.copy(argdump, work / "argdump.exe")
dump_file = work / "dump.txt"
ENV["ARGDUMP_OUT"] = dump_file.to_s
{false, true}.each do |rare|
  failures = 0
  injections = 0
  errors = 0
  samples = [] of Hash(String, String)
  cases = 1500
  cases.times do |i|
    args = random_args(rng, allow_rare: rare)
    args << %("&echo injected>"#{work}\\inj.txt") if i % 10 == 0
    File.delete?(dump_file)
    File.delete?(work / "inj.txt")
    line = %(cmd.exe /e:ON /v:OFF /d /c ""#{wrapper}") + args.map { |a| " " + bat_arg(a) }.join + %(")
    code = raw_run(line)
    injections += 1 if File.exists?(work / "inj.txt")
    unless code == 0 && File.exists?(dump_file)
      errors += 1
      samples << {"args" => args.inspect, "line" => line, "error" => "exit #{code}"} if samples.size < 8
      next
    end
    got = File.read(dump_file).split('\n')[0...-1]
    expected = args.map { |a| hex(a) }
    next if got == expected
    failures += 1
    samples << {"args" => args.inspect, "line" => line, "got_hex" => got.inspect}
  end
  report "cmd_quoting_candidate#{rare ? "_with_newlines" : ""}", cases, failures, samples, injections: injections, errors: errors
end
