# Can a Crystal program be a Windows service, and what does the SCM do to its ProcessSupervision children?
# (explore-hard.yml, elevated runners.)
#
# The SCM calls ServiceMain on a thread it creates (not a Crystal thread), and the control handler on the thread that
# called StartServiceCtrlDispatcherW. So the dispatcher runs on a Crystal `Thread`, ServiceMain only calls the Win32 API
# (register the handler, report RUNNING, signal an event) and the Crystal work stays on the main thread.
# Scenario "alloc" allocates Crystal objects inside ServiceMain, on the foreign thread, to see what that does.
#
# Usage: crystal_service <work dir>                         controller: create, start, stop, kill, delete the service
#        crystal_service --service <log> <scenario>         as started by the SCM
#        crystal_service --sleep                            the worker child
require "json"
require "process-supervision"

@[Link("advapi32")]
lib LibSvc
  alias ServiceMain = UInt32, UInt16** -> Void
  alias Handler = UInt32, UInt32, Void*, Void* -> UInt32

  struct SERVICE_TABLE_ENTRYW
    name : UInt16*
    proc : ServiceMain
  end

  struct SERVICE_STATUS
    service_type : UInt32
    current_state : UInt32
    controls_accepted : UInt32
    win32_exit_code : UInt32
    specific_exit_code : UInt32
    check_point : UInt32
    wait_hint : UInt32
  end

  fun StartServiceCtrlDispatcherW(table : SERVICE_TABLE_ENTRYW*) : Int32
  fun RegisterServiceCtrlHandlerExW(name : UInt16*, handler : Handler, context : Void*) : Void*
  fun SetServiceStatus(handle : Void*, status : SERVICE_STATUS*) : Int32
end

lib LibSvcKernel
  fun CreateEventW(attributes : Void*, manual_reset : Int32, initial : Int32, name : UInt16*) : Void*
  fun SetEvent(event : Void*) : Int32
end

module Svc
  # numeric literals: statically initialised, so reading them on the SCM's thread runs no Crystal initialiser
  @@status_handle = 0_u64
  @@started_event = 0_u64
  @@stop_event = 0_u64
  @@name = 0_u64
  @@scenario = 0
  @@service_main_thread = 0_u32
  @@handler_thread = 0_u32
  @@alloc_result = 0_u64
  @@stop_controls = 0

  class_property status_handle, started_event, stop_event, name, scenario, service_main_thread, handler_thread, alloc_result, stop_controls

  def self.report(state : UInt32, wait_hint = 0_u32, exit_code = 0_u32) : Nil
    status = LibSvc::SERVICE_STATUS.new
    status.service_type = 0x10_u32 # SERVICE_WIN32_OWN_PROCESS
    status.current_state = state
    status.controls_accepted = state == 4_u32 ? 0x5_u32 : 0_u32 # STOP | SHUTDOWN while running
    status.win32_exit_code = exit_code
    status.wait_hint = wait_hint
    LibSvc.SetServiceStatus(Pointer(Void).new(@@status_handle), pointerof(status))
  end

  def self.service_main : Nil
    @@service_main_thread = LibC.GetCurrentThreadId
    if @@scenario == 1
      text = "allocated on the SCM thread #{LibC.GetCurrentThreadId} #{[1, 2, 3].sum}"
      @@alloc_result = text.bytesize.to_u64
    end
    handler = ->(control : UInt32, event_type : UInt32, event_data : Void*, context : Void*) do
      Svc.handler_thread = LibC.GetCurrentThreadId
      case control
      when 1_u32, 5_u32 # STOP, SHUTDOWN
        Svc.stop_controls += 1
        Svc.report(3_u32, 10_000_u32) # STOP_PENDING
        LibSvcKernel.SetEvent(Pointer(Void).new(Svc.stop_event))
        0_u32
      when 4_u32 then 0_u32 # INTERROGATE
      else            120_u32
      end
    end
    @@status_handle = LibSvc.RegisterServiceCtrlHandlerExW(Pointer(UInt16).new(@@name), handler, Pointer(Void).null).address
    report(4_u32) # RUNNING
    LibSvcKernel.SetEvent(Pointer(Void).new(@@started_event))
  end
end

def emit(kind : String, **fields)
  puts({"case" => kind}.merge(fields.to_h.transform_keys(&.to_s)).to_json)
  STDOUT.flush
end

case ARGV.first?
when "--sleep"
  sleep 600.seconds
  exit 0
when "--service"
  log = File.open(ARGV[1], "a")
  log.sync = true
  Svc.scenario = ARGV[2] == "alloc" ? 1 : 0
  log.puts "main pid=#{Process.pid} thread=#{LibC.GetCurrentThreadId} scenario=#{ARGV[2]}"
  {STDIN, STDOUT, STDERR}.each_with_index do |io, i|
    log.puts "std#{i} tty=#{io.tty? rescue "error"}"
  end
  begin
    STDOUT.puts "hello from a service"
    STDOUT.flush
    log.puts "stdout write ok"
  rescue ex
    log.puts "stdout write raised #{ex.class}: #{ex.message}"
  end
  service_name = "crprobe".to_utf16
  Svc.name = service_name.to_unsafe.address
  Svc.started_event = LibSvcKernel.CreateEventW(nil, 1, 0, nil).address
  Svc.stop_event = LibSvcKernel.CreateEventW(nil, 1, 0, nil).address
  dispatch_result = -1
  dispatch_error = 0_u32
  dispatcher = Thread.new("scm-dispatcher") do
    table = StaticArray(LibSvc::SERVICE_TABLE_ENTRYW, 2).new(LibSvc::SERVICE_TABLE_ENTRYW.new)
    entry = LibSvc::SERVICE_TABLE_ENTRYW.new
    entry.name = service_name.to_unsafe
    entry.proc = ->(argc : UInt32, argv : UInt16**) { Svc.service_main }
    table[0] = entry
    dispatch_result = LibSvc.StartServiceCtrlDispatcherW(table.to_unsafe)
    dispatch_error = LibC.GetLastError
  end
  waited = LibC.WaitForSingleObject(Pointer(Void).new(Svc.started_event), 30_000_u32)
  log.puts "started wait=#{waited} service_main_thread=#{Svc.service_main_thread} alloc_result=#{Svc.alloc_result}"
  if waited != 0
    log.puts "dispatcher result=#{dispatch_result} error=#{dispatch_error}"
    exit 2
  end
  begin
    output = IO::Memory.new
    status = Process.run("cmd.exe", ["/c", "echo child-of-service"], output: output)
    log.puts "Process.run status=#{status.exit_code} output=#{output.to_s.strip}"
  rescue ex
    log.puts "Process.run raised #{ex.class}: #{ex.message}"
  end
  job = ProcessSupervision.job
  worker = job.spawn(Process.executable_path.not_nil!, ["--sleep"])
  log.puts "worker pid=#{worker.pid}"
  LibC.WaitForSingleObject(Pointer(Void).new(Svc.stop_event), LibC::INFINITE)
  stop_seen = Time.utc
  log.puts "stop seen handler_thread=#{Svc.handler_thread} controls=#{Svc.stop_controls}"
  result = job.shutdown(grace: 1.second, kill_after: 2.seconds)
  log.puts "job shutdown #{result.inspect} in #{(Time.utc - stop_seen).total_milliseconds.round(1)} ms"
  Svc.report(1_u32) # STOPPED
  dispatcher.join
  log.puts "dispatcher returned result=#{dispatch_result} error=#{dispatch_error}"
  exit 0
end

# controller
work = Path[ARGV[0]? || "svc-work"].expand
Dir.mkdir_p(work)
exe = Process.executable_path.not_nil!

def sc(*args : String) : String
  output = IO::Memory.new
  Process.run("sc.exe", args.to_a, output: output, error: output)
  output.to_s
end

def query(name) : {String, Int64}
  text = sc("queryex", name)
  state = text[/STATE\s*:\s*\d+\s+(\w+)/, 1]? || "?"
  pid = (text[/PID\s*:\s*(\d+)/, 1]? || "0").to_i64
  {state, pid}
end

def alive?(pid : Int64) : Bool
  return false if pid <= 0
  output = IO::Memory.new
  Process.run("tasklist.exe", ["/FI", "PID eq #{pid}", "/NH"], output: output)
  output.to_s.includes?(" #{pid} ")
end

def wait_for(timeout : Time::Span, &) : Bool
  deadline = Time.instant + timeout
  until yield
    return false if Time.instant > deadline
    sleep 20.milliseconds
  end
  true
end

def log_worker(log : Path) : Int64
  File.exists?(log) ? (File.read(log)[/worker pid=(\d+)/, 1]? || "0").to_i64 : 0_i64
end

{"minimal", "alloc"}.each do |scenario|
  {"stop", "kill"}.each do |ending|
    name = "crprobe-#{scenario}-#{ending}"
    log = work / "#{name}.log"
    File.delete?(log)
    sc("stop", name)
    sc("delete", name)
    bin = %("#{exe}" --service "#{log}" #{scenario})
    created = sc("create", name, "binPath=", bin, "start=", "demand")
    started_at = Time.instant
    start_out = sc("start", name)
    running = wait_for(30.seconds) { query(name)[0].in?("RUNNING", "STOPPED") }
    state, service_pid = query(name)
    start_ms = (Time.instant - started_at).total_milliseconds.round(1)
    wait_for(10.seconds) { log_worker(log) > 0 || !alive?(service_pid) }
    worker = log_worker(log)
    worker_alive = alive?(worker)
    stop_ms = nil
    worker_after = nil
    service_after = nil
    if ending == "stop"
      t = Time.instant
      sc("stop", name)
      wait_for(30.seconds) { query(name)[0] == "STOPPED" }
      stop_ms = (Time.instant - t).total_milliseconds.round(1)
    else
      t = Time.instant
      Process.run("taskkill.exe", ["/F", "/PID", service_pid.to_s], output: Process::Redirect::Close)
      wait_for(10.seconds) { !alive?(service_pid) }
      stop_ms = (Time.instant - t).total_milliseconds.round(1)
    end
    wait_for(5.seconds) { !alive?(worker) }
    worker_after = alive?(worker)
    service_after = alive?(service_pid)
    final_state = query(name)[0]
    sc("delete", name)
    emit "service", scenario: scenario, ending: ending, created: created.strip.lines.last?, start_state: state,
      start_ms: start_ms, reached_running_or_stopped: running, service_pid: service_pid, worker_pid: worker,
      worker_alive_while_running: worker_alive, end_ms: stop_ms, worker_alive_after: worker_after,
      service_alive_after: service_after, final_state: final_state,
      start_output: start_out.lines.select(&.includes?("FAILED")).first?,
      log: File.exists?(log) ? File.read(log).lines : [] of String
    Process.run("taskkill.exe", ["/F", "/PID", worker.to_s], output: Process::Redirect::Close) if worker_after
  end
end
