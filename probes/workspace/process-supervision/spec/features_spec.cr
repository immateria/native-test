require "./spec_helper"
require "file_utils"

# Specs for the spawn options, group control, usage/snapshot, exit outcomes, the lifeline, cgroup limits and the
# supervisor. Included from process_supervision_spec.cr so the existing build and CI run them.

{% if flag?(:unix) %}
  lib LibFeatureSpec
    fun getsid(pid : Int32) : Int32
  end

  private def feature_leader(command : String, args = [] of String, **options) : ProcessSupervision::Child
    ProcessSupervision::POSIX::ProcessGroup.spawn_leader(command, args, **options)
  end

  private def feature_finish(child : ProcessSupervision::Child) : Process::Status
    status = child.wait(10.seconds).not_nil!
    child.close
    child.group.close rescue nil
    status
  end

  private def process_state(pid : Int64) : String
    {% if flag?(:linux) %}
      stat = File.read("/proc/#{pid}/stat")
      stat[(stat.rindex(')').not_nil! + 2)..].split(' ').first
    {% else %}
      `ps -o stat= -p #{pid}`.strip
    {% end %}
  end

  private def eventually(within : Time::Span = 5.seconds, & : -> Bool) : Bool
    deadline = Time.instant + within
    loop do
      return true if yield
      return false if Time.instant > deadline
      sleep 20.milliseconds
    end
  end

  private def options(&) : ProcessSupervision::SpawnOptions
    value = ProcessSupervision::SpawnOptions.new
    yield value
    value
  end

  describe "ProcessSupervision::SpawnOptions (POSIX)" do
    it "starts a leader in a new session" do
      child = feature_leader("sleep", ["5"], options: options(&.new_session=(true)))
      begin
        LibFeatureSpec.getsid(child.pid.to_i32).should eq(child.pid.to_i32)
        LibC.getpgid(child.pid.to_i32).should eq(child.pid.to_i32)
      ensure
        child.group.kill
        feature_finish(child)
      end
    end

    it "refuses a new session for a child joining an existing group" do
      first = feature_leader("sleep", ["5"])
      begin
        group = first.group.as(ProcessSupervision::POSIX::ProcessGroup)
        expect_raises(ProcessSupervision::Error::Unsupported) { group.spawn("true", options: options(&.new_session=(true))) }
      ensure
        first.group.kill
        feature_finish(first)
      end
    end

    it "passes extra descriptors at the numbers asked for" do
      reader, writer = IO.pipe
      child = feature_leader("/bin/sh", ["-c", "echo via5 >&5"], options: options { |o| o.extra_fds[5] = writer })
      writer.close
      feature_finish(child).success?.should be_true
      reader.gets.should eq("via5")
      reader.close
    end

    it "gives the child an IPC socket and announces its descriptor" do
      script = %q(eval "echo hello >&$PROCESS_SUPERVISION_IPC_FD"; eval "read line <&$PROCESS_SUPERVISION_IPC_FD"; echo "got $line")
      child = feature_leader("/bin/sh", ["-c", script], output: Process::Redirect::Pipe, options: options(&.ipc=(true)))
      begin
        child.ipc.gets.should eq("hello")
        child.ipc.puts "back"
        child.output.gets.should eq("got back")
      ensure
        feature_finish(child)
      end
    end

    {% if flag?(:linux) %}
      it "applies resource limits, umask and no_new_privs in the child (clone3/fork engine)" do
        opts = options do |o|
          o.rlimits[ProcessSupervision::SpawnOptions::Rlimit::Nofile] = {64_u64, 64_u64}
          o.umask = 0o077_u32
          o.no_new_privileges = true
        end
        child = feature_leader("/bin/sh", ["-c", "ulimit -n; umask; grep NoNewPrivs /proc/self/status"],
          output: Process::Redirect::Pipe, options: opts)
        ProcessSupervision::Linux::RawSpawn.last_engine.should_not eq("pidfd_spawn")
        lines = child.output.gets_to_end.lines
        feature_finish(child).success?.should be_true
        lines[0].should eq("64")
        lines[1].should eq("0077")
        lines[2].split.last.should eq("1")
      end

      it "starts the child with a parent-death signal" do
        child = feature_leader("/bin/sh", ["-c", "true"], options: options(&.parent_death_signal=(Signal::KILL)))
        feature_finish(child).success?.should be_true
      end

      it "switches user and group when running as root" do
        pending!("needs root") unless LibC.getuid == 0
        opts = options do |o|
          o.gid = 65534_u32
          o.groups = [65534_u32]
          o.uid = 65534_u32
        end
        child = feature_leader("/bin/sh", ["-c", "id -u; id -g"], output: Process::Redirect::Pipe, options: opts)
        text = child.output.gets_to_end
        feature_finish(child).success?.should be_true
        text.lines.should eq(["65534", "65534"])
      end

      it "starts the child in new UTS and PID namespaces when privileged" do
        pending!("needs root") unless LibC.getuid == 0
        opts = options { |o| o.namespaces = ProcessSupervision::SpawnOptions::Namespace::Uts | ProcessSupervision::SpawnOptions::Namespace::Pid }
        child = begin
          # never touch the hostname unless this really is the new PID namespace (so also the new UTS one)
          feature_leader("/bin/sh", ["-c", "[ $$ = 1 ] || exit 9; hostname ps-ns-spec; hostname; echo $$"], output: Process::Redirect::Pipe, options: opts)
        rescue ex : ProcessSupervision::Error::Unsupported | File::AccessDeniedError | IO::Error
          pending!("namespaces refused here: #{ex.message}")
        end
        text = child.output.gets_to_end
        feature_finish(child)
        text.lines.should eq(["ps-ns-spec", "1"])
        System.hostname.should_not eq("ps-ns-spec")
      end
    {% else %}
      it "refuses options macOS's posix_spawn cannot express" do
        opts = options { |o| o.rlimits[ProcessSupervision::SpawnOptions::Rlimit::Core] = {0_u64, 0_u64} }
        expect_raises(ProcessSupervision::Error::Unsupported) { feature_leader("true", options: opts) }
      end
    {% end %}
  end

  describe "ProcessSupervision group control (POSIX)" do
    it "suspends and resumes a process group" do
      child = feature_leader("sleep", ["30"])
      group = child.group
      begin
        group.suspend
        eventually { process_state(child.pid).starts_with?("T") }.should be_true
        group.resume
        eventually { !process_state(child.pid).starts_with?("T") }.should be_true
      ensure
        group.kill
        feature_finish(child)
      end
    end

    it "delivers an arbitrary signal to the group" do
      script = %q(trap 'echo hup' HUP; echo ready; while :; do sleep 0.05; done)
      child = feature_leader("/bin/sh", ["-c", script], output: Process::Redirect::Pipe)
      begin
        child.output.gets.should eq("ready")
        child.group.signal(Signal::HUP)
        child.output.gets.should eq("hup")
      ensure
        child.group.kill
        feature_finish(child)
      end
    end

    it "stops a group gracefully: a TERM handler runs and no kill is needed, even when suspended" do
      script = %q(trap 'echo bye; exit 0' TERM; echo ready; while :; do sleep 0.05; done)
      child = feature_leader("/bin/sh", ["-c", script], output: Process::Redirect::Pipe)
      child.output.gets.should eq("ready")
      child.group.suspend
      result = child.group.stop(grace: 5.seconds, kill_after: 2.seconds)
      result.terminate_requested?.should be_true
      result.kill_requested?.should be_false
      child.output.gets.should eq("bye")
      child.wait(5.seconds).not_nil!.success?.should be_true
      child.close
    end

    it "reads a child's resource usage and finds it in a process snapshot" do
      child = feature_leader("sleep", ["5"])
      begin
        usage = child.handle.usage
        usage.resident_bytes.not_nil!.should be > 0
        usage.cpu_time.should be >= Time::Span.zero
        snapshot = ProcessHandle.snapshot
        entry = snapshot.find { |candidate| candidate.pid == child.pid }.not_nil!
        entry.parent_pid.should eq(Process.pid)
        ProcessHandle.descendants(Process.pid, snapshot).map(&.pid).should contain(child.pid)
      ensure
        child.group.kill
        feature_finish(child)
      end
    end

    it "classifies exits, signals and crashes" do
      exited = feature_leader("/bin/sh", ["-c", "exit 3"])
      feature_finish(exited)
      exited.outcome.not_nil!.kind.exited?.should be_true
      exited.outcome.not_nil!.code.should eq(3)

      killed = feature_leader("sleep", ["30"])
      killed.group.signal(Signal::TERM)
      feature_finish(killed)
      killed.outcome.not_nil!.kind.signaled?.should be_true
      killed.outcome.not_nil!.signal.should eq(Signal::TERM)

      crashed = feature_leader("/bin/sh", ["-c", "kill -SEGV $$"])
      feature_finish(crashed)
      crashed.outcome.not_nil!.crashed?.should be_true
    end

    it "kills the group when the lifeline's writer goes away (the supervisor died), and not after disarm" do
      child = feature_leader("sleep", ["30"])
      group = child.group
      lifeline = ProcessSupervision::Lifeline.arm(group)
      lifeline.armed?.should be_true
      lifeline.disarm
      sleep 200.milliseconds
      group.empty?.should be_false

      lifeline = ProcessSupervision::Lifeline.arm(group)
      # what the kernel does when the supervisor dies: the only writer of the watcher's pipe is closed
      lifeline.watcher.not_nil!.input.close
      group.wait_empty(5.seconds).should be_true
      child.wait(5.seconds).not_nil!.exit_signal?.should eq(Signal::KILL)
      lifeline.watcher.not_nil!.wait(5.seconds)
      child.close
      group.close
    end
  end
{% end %}

{% if flag?(:linux) %}
  private def feature_cgroup : ProcessSupervision::Linux::CgroupV2
    parent = ProcessSupervision::Linux::CgroupV2.delegated_parent
    pending!("no cgroup is delegated to this process in this environment") unless parent
    ProcessSupervision::Linux::CgroupV2.create(parent.not_nil!, "ps-feature-#{Process.pid}-#{Random.new.hex(4)}")
  end

  describe "ProcessSupervision::Linux::CgroupV2 control" do
    it "freezes and thaws the whole subtree, signals members and reports them" do
      group = feature_cgroup
      child = group.spawn("/bin/sh", ["-c", "sleep 30 & sleep 30 & wait"])
      begin
        eventually { group.members.size == 3 }.should be_true
        group.suspend
        group.frozen?.should be_true
        group.resume
        group.frozen?.should be_false
        group.signal(Signal::TERM)
        group.wait_empty(5.seconds).should be_true
      ensure
        group.kill rescue nil
        child.wait(5.seconds)
        child.close
        group.close
      end
    end

    it "reads cpu statistics" do
      group = feature_cgroup
      child = group.spawn("/bin/sh", ["-c", "i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done"])
      begin
        child.wait(30.seconds).not_nil!.success?.should be_true
        group.stats.cpu_usage.not_nil!.should be > Time::Span.zero
      ensure
        child.close
        group.close
      end
    end

    it "limits the number of processes once the pids controller is enabled for it" do
      outer = feature_cgroup
      begin
        enabled = begin
          ProcessSupervision::Linux::CgroupV2.enable_controllers(outer.path, ["pids"])
        rescue ex : ProcessSupervision::Error
          pending!("controllers cannot be enabled here: #{ex.message}")
        end
        pending!("the pids controller is not delegated here") unless enabled.includes?("pids")
        inner = ProcessSupervision::Linux::CgroupV2.create(outer.path, "limited")
        inner.limits = ProcessSupervision::Linux::CgroupV2::Limits.new(pids_max: 3_i64)
        child = inner.spawn("/bin/sh", ["-c", "for i in 1 2 3 4 5 6; do sleep 2 & done; wait"], error: Process::Redirect::Pipe)
        errors = child.error.gets_to_end
        child.wait(30.seconds)
        child.close
        inner.close
        errors.should_not be_empty # some forks were refused (EAGAIN)
      ensure
        outer.close rescue nil
      end
    end

    it "obtains a delegated cgroup from systemd" do
      scope = begin
        ProcessSupervision::Linux::SystemdScope.acquire
      rescue ex : ProcessSupervision::Error::Unavailable
        pending!(ex.message || "systemd scope unavailable")
      end
      begin
        group = ProcessSupervision::Linux::CgroupV2.create(scope.path, "workers")
        child = group.spawn("/bin/sh", ["-c", "cat /proc/self/cgroup"], output: Process::Redirect::Pipe)
        child.output.gets_to_end.should contain(scope.unit)
        child.wait(5.seconds)
        child.close
        group.close
      ensure
        scope.close
      end
    end
  end
{% end %}

{% if flag?(:unix) %}
  describe ProcessSupervision::Supervisor do
    it "restarts a failing service with backoff and gives up after the intensity limit" do
      supervisor = ProcessSupervision::Supervisor.new
      spec = ProcessSupervision::Supervisor::Spec.new("flaky", "/bin/sh", ["-c", "echo run; exit 3"])
      spec.max_restarts = 2
      spec.backoff_min = 20.milliseconds
      supervisor.add(spec)
      supervisor.start
      kinds = [] of ProcessSupervision::Supervisor::EventKind
      loop do
        event = supervisor.events.receive
        kinds << event.kind
        break if event.kind.gave_up? || kinds.size > 50
      end
      supervisor.stop
      kinds.count(&.restarting?).should eq(2)
      kinds.should contain(ProcessSupervision::Supervisor::EventKind::GaveUp)
      supervisor["flaky"].state.failed?.should be_true
      supervisor["flaky"].log.lines.map(&.text).should eq(["run", "run", "run"])
      supervisor["flaky"].last_outcome.not_nil!.code.should eq(3)
    end

    it "waits for sd_notify readiness and starts dependants after it" do
      python = Process.find_executable("python3")
      pending!("python3 is not installed") unless python
      supervisor = ProcessSupervision::Supervisor.new
      script = "import os,socket,time; s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); time.sleep(0.2); " \
               "s.sendto(b'STATUS=warm\\nREADY=1', os.environ['NOTIFY_SOCKET']); time.sleep(0.5)"
      first = ProcessSupervision::Supervisor::Spec.new("first", python.not_nil!, ["-c", script])
      first.readiness = ProcessSupervision::Supervisor::Readiness::Notify
      first.restart = ProcessSupervision::Supervisor::Restart::Never
      second = ProcessSupervision::Supervisor::Spec.new("second", "/bin/sh", ["-c", "echo second"])
      second.depends_on = ["first"]
      second.restart = ProcessSupervision::Supervisor::Restart::Never
      supervisor.add(first)
      supervisor.add(second)
      supervisor.start
      order = [] of String
      until order.includes?("second:Exited")
        event = supervisor.events.receive
        order << "#{event.service}:#{event.kind}"
      end
      supervisor.stop
      order.index("first:Ready").not_nil!.should be < order.index("second:Starting").not_nil!
      supervisor["first"].status_text.should eq("warm")
    end

    it "restarts a service whose watchdog stops" do
      supervisor = ProcessSupervision::Supervisor.new
      spec = ProcessSupervision::Supervisor::Spec.new("silent", "sleep", ["30"])
      spec.watchdog = 300.milliseconds
      spec.restart = ProcessSupervision::Supervisor::Restart::Always
      spec.backoff_min = 20.milliseconds
      spec.stop_grace = 1.second
      supervisor.add(spec)
      supervisor.start
      kinds = [] of ProcessSupervision::Supervisor::EventKind
      until kinds.includes?(ProcessSupervision::Supervisor::EventKind::Restarting)
        kinds << supervisor.events.receive.kind
      end
      supervisor.stop
      kinds.should contain(ProcessSupervision::Supervisor::EventKind::Unhealthy)
    end

    it "keeps a bounded log" do
      log = ProcessSupervision::LineLog.new("out", 3)
      log.print "a\nb\nc\nd\npartial"
      log.flush
      log.lines.map(&.text).should eq(["c", "d", "partial"])
    end
  end

  describe "stress (PROCESS_SUPERVISION_STRESS=1)" do
    it "leaves descriptors and children flat over many spawn / stream / kill cycles" do
      pending!("set PROCESS_SUPERVISION_STRESS=1") unless ENV["PROCESS_SUPERVISION_STRESS"]? == "1"
      fd_directory = File.directory?("/proc/self/fd") ? "/proc/self/fd" : "/dev/fd"
      before = Dir.children(fd_directory).size
      200.times do |index|
        child = ProcessSupervision.spawn("/bin/sh", ["-c", "echo #{index}; sleep 5"],
          input: IO::Memory.new("x"), output: Process::Redirect::Pipe)
        child.output.gets.should eq(index.to_s)
        child.group.stop(grace: 1.second, kill_after: 1.second)
        child.wait(5.seconds)
        child.close
      end
      Dir.children(fd_directory).size.should be <= before + 2
    end
  end
{% end %}

{% if flag?(:win32) %}
  private def windows_child : String
    path = ENV["PROCESS_SUPERVISION_STDIO_CHILD"]?
    pending!("PROCESS_SUPERVISION_STDIO_CHILD is not set") unless path && File.exists?(path)
    path
  end

  describe "ProcessSupervision Windows control" do
    it "lists, suspends and resumes Job members and reads their usage" do
      job = ProcessSupervision.job
      child = job.spawn(windows_child, ["ready"], output: Process::Redirect::Pipe)
      begin
        child.output.gets.should eq("ready")
        job.process_ids.should contain(child.pid)
        job.suspend
        job.resume
        usage = child.handle.usage
        usage.resident_bytes.not_nil!.should be > 0
        ProcessHandle.snapshot.find { |entry| entry.pid == child.pid }.not_nil!.parent_pid.should eq(Process.pid)
      ensure
        job.kill
        child.wait(5.seconds)
        child.close
        job.close
      end
    end

    it "stops a console child gracefully with CTRL_BREAK" do
      job = ProcessSupervision.job
      options = ProcessSupervision::SpawnOptions.new
      options.console_group = true
      child = job.spawn(windows_child, ["break"], output: Process::Redirect::Pipe, options: options)
      begin
        child.output.gets.should eq("ready")
        result = job.stop(grace: 5.seconds, kill_after: 2.seconds, close: false)
        result.kill_requested?.should be_false
        child.output.gets.not_nil!.should start_with("stopping")
      ensure
        child.wait(5.seconds)
        child.close
        job.close
      end
    end

    it "ends a crashing child at once with die_on_unhandled_exception and classifies the crash" do
      job = ProcessSupervision.job(ProcessSupervision::Windows::Job::Limits.new(die_on_unhandled_exception: true))
      child = job.spawn(windows_child, ["crash"])
      begin
        status = child.wait(10.seconds).not_nil!
        outcome = ProcessSupervision::ExitOutcome.classify(status)
        outcome.crashed?.should be_true
        outcome.description.should contain("ACCESS_VIOLATION")
      ensure
        child.close
        job.close
      end
    end

    it "passes an extra handle and announces its value" do
      reader, writer = IO.pipe(read_blocking: false, write_blocking: true)
      options = ProcessSupervision::SpawnOptions.new
      options.extra_fds[5] = writer
      job = ProcessSupervision.job
      child = job.spawn(windows_child, ["write-handle"], options: options)
      begin
        writer.close
        reader.gets.should eq("via handle")
        child.wait(5.seconds).not_nil!.success?.should be_true
      ensure
        child.close
        job.close
      end
    end

    it "rejects options Windows cannot honour and command lines that are too long" do
      options = ProcessSupervision::SpawnOptions.new
      options.uid = 0_u32
      expect_raises(ProcessSupervision::Error::Unsupported) { ProcessSupervision.job.spawn(windows_child, options: options) }
      job = ProcessSupervision.job
      error = expect_raises(ProcessSupervision::Error::Native) { job.spawn(windows_child, ["x" * 40_000]) }
      error.native_code.should eq(206) # ERROR_FILENAME_EXCED_RANGE, as CreateProcessW reports it
      job.empty?.should be_true
      job.close
    end
  end
{% end %}
