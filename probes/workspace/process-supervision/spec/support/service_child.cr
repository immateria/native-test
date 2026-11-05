# A supervisor that runs as a Windows service, for the service spec. The SCM starts it as
#   service_child <log file> <service name>
# It starts one worker (this program with --sleep) in a Job, logs the worker's pid, waits for STOP and shuts the Job
# down. Build it and point PROCESS_SUPERVISION_SERVICE_CHILD at the executable; the spec is pending without it.
require "../../src/process-supervision"

if ARGV.first? == "--sleep"
  sleep 600.seconds
  exit 0
end

log = File.open(ARGV[0], "a")
log.sync = true
log.puts "started pid=#{Process.pid}"
begin
  ProcessSupervision::Windows::Service.run(ARGV[1]) do |service|
    job = ProcessSupervision.job
    worker = job.spawn(Process.executable_path.not_nil!, ["--sleep"])
    log.puts "worker=#{worker.pid}"
    service.wait_for_stop
    log.puts "stop requested"
    service.report_stop_progress(10.seconds)
    result = job.shutdown(grace: 1.second, kill_after: 2.seconds)
    log.puts "shutdown drained=#{result.drained?}"
  end
  log.puts "service returned"
rescue ex
  log.puts "error #{ex.class}: #{ex.message}"
end
