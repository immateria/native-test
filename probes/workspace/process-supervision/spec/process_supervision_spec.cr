require "./spec_helper"
require "file_utils"

# Several examples use the spec process's own group as a stand-in group. Inside a container the spec binary is
# commonly PID 1 and leads process group 1, which ProcessGroup refuses to address (kill(-1, sig) is a broadcast).
private def spec_pgid : Int64
  pgid = Process.pgid
  pending!("this process leads process group 1 (PID 1 of a container)") if pgid == 1
  pgid
end

private class ShutdownFailureGroup < ProcessSupervision::Group
  getter close_calls = 0

  def initialize(@fail_close : Bool = false)
  end

  def mechanism : ProcessSupervision::Mechanism
    ProcessSupervision::Mechanism::ProcessGroup
  end

  def kill_on_close? : Bool
    false
  end

  def soft_termination? : Bool
    true
  end

  def empty? : Bool
    raise ProcessSupervision::Error::Native.new("initial empty?", "injected failure")
  end

  def wait_empty(timeout : Time::Span? = nil) : Bool
    false
  end

  def terminate : Nil
  end

  def kill : Nil
  end

  def close : Nil
    @close_calls += 1
    raise ProcessSupervision::Error::Native.new("injected close", "cleanup failure") if @fail_close
  end

  def closed? : Bool
    @close_calls > 0
  end
end

describe "ProcessSupervision::Group shutdown cleanup" do
  it "closes the group if the initial empty check raises, preserving that error" do
    group = ShutdownFailureGroup.new
    ex = expect_raises(ProcessSupervision::Error::Native) do
      group.shutdown(close: true)
    end
    ex.message.not_nil!.should contain("initial empty?")
    group.close_calls.should eq(1)
  end

  it "preserves the original shutdown error if its cleanup also fails" do
    group = ShutdownFailureGroup.new(fail_close: true)
    ex = expect_raises(ProcessSupervision::Error::Native) do
      group.shutdown(close: true)
    end
    ex.message.not_nil!.should contain("initial empty?")
    group.close_calls.should eq(1)
  end

  it "does not touch the group after invalid timeout arguments" do
    group = ShutdownFailureGroup.new
    expect_raises(ArgumentError) { group.shutdown(grace: -1.millisecond) }
    group.close_calls.should eq(0)
  end
end

{% if flag?(:unix) %}
  describe ProcessSupervision::POSIX::ProcessGroup do
    it "observes an existing process group without claiming kill-on-close" do
      group = ProcessSupervision.process_group(spec_pgid)
      group.mechanism.should eq(ProcessSupervision::Mechanism::ProcessGroup)
      group.kill_on_close?.should be_false
      group.soft_termination?.should be_true
      group.empty?.should be_false
      group.close
      group.closed?.should be_true
    end

    it "treats a nonexistent process group as empty" do
      group = ProcessSupervision.process_group(Int32::MAX)
      group.empty?.should be_true
      group.wait_empty(10.milliseconds).should be_true
    ensure
      group.try &.close
    end
  end
{% else %}
  describe ProcessSupervision do
    it "loads the public surface" do
      ProcessSupervision::VERSION.should eq("0.7.0")
    end
  end
{% end %}

{% if flag?(:linux) %}
  describe ProcessSupervision::Linux::CgroupV2 do
    it "discovers the mounted v2 hierarchy and the current cgroup" do
      mount = ProcessSupervision::Linux::CgroupV2.mountpoint
      ProcessSupervision::Linux::CgroupV2.available?.should eq(!mount.nil?)
      if mount
        File.directory?(mount).should be_true
        current = ProcessSupervision::Linux::CgroupV2.current_path
        current.should_not be_nil
        current.not_nil!.to_s.starts_with?(mount.to_s).should be_true
      end
    end

    it "never opens the machine's hierarchy root as a killable supervision group" do
      mount = ProcessSupervision::Linux::CgroupV2.mountpoint
      pending!("no cgroup-v2 mount") unless mount
      if File.readlink("/proc/self/ns/cgroup") == "cgroup:[4026531835]"
        expect_raises(ArgumentError, /hierarchy root/) do
          ProcessSupervision::Linux::CgroupV2.open(mount.not_nil!)
        end
      else
        # a private cgroup namespace (a container): the mount root is only the container's own cgroup, an ordinary
        # cgroup on the host, so it may be opened (killing it kills the caller, as for any cgroup the caller is in)
        ProcessSupervision::Linux::CgroupV2.open(mount.not_nil!).close
      end
    end

    it "makes a weaker process-group fallback observable" do
      missing = Path["/definitely-missing-process-supervision-cgroup"]
      group = ProcessSupervision.cgroup_v2(missing, fallback_pgid: spec_pgid)
      group.mechanism.should eq(ProcessSupervision::Mechanism::ProcessGroup)
      group.kill_on_close?.should be_false
      group.close
    end
  end
{% end %}

{% if flag?(:linux) %}
  describe ProcessSupervision::Child do
    it "returns the spawned child's exit status after a stable-handle wait" do
      process = Process.new(
        "/bin/sh", ["-c", "sleep 0.05; exit 7"],
        input: Process::Redirect::Close,
        output: Process::Redirect::Close,
        error: Process::Redirect::Close
      )
      handle = ProcessHandle.open(process.pid)
      group = ProcessSupervision.process_group(spec_pgid)
      child = ProcessSupervision::Child.new(process, handle, group)

      status = child.wait(2.seconds)
      status.should_not be_nil
      status.not_nil!.exit_code.should eq(7)
      child.status.should eq(status)
    ensure
      child.try &.close
      handle.try { |value| value.close unless value.closed? }
      process.try &.close
      group.try &.close
    end
  end
{% end %}

# Until native Windows execution is available in every development host, keep
# the race-free creation ordering as an executable source contract as well as a
# cross-target typecheck. Native Windows verification remains the stronger gate.
describe "Windows supervised-spawn source contract" do
  it "contains the child at creation and verifies assignment before resume" do
    source = File.read(Path[__DIR__].parent / "src/process-supervision/windows/spawn.cr")
    source.should contain("PROC_THREAD_ATTRIBUTE_JOB_LIST")
    source.should contain("PROC_THREAD_ATTRIBUTE_HANDLE_LIST")
    source.should contain("CREATE_SUSPENDED")

    job_attr = source.index("PROC_THREAD_ATTRIBUTE_JOB_LIST").not_nil!
    create = source.index("LibC.CreateProcessW").not_nil!
    assign = source.index("LibC.AssignProcessToJobObject").not_nil!
    stable = source.index("ProcessHandle.open").not_nil!
    resume = source.index("Crystal::System::Process.new").not_nil!

    job_attr.should be < create
    create.should be < assign
    assign.should be < stable
    stable.should be < resume
  end
end

{% if flag?(:linux) %}
  describe "ProcessSupervision PTY-derived lifecycle contracts" do
    it "fans one child wait status out to simultaneous callers" do
      process = Process.new(
        "/bin/sh", ["-c", "read line; exit 23"],
        input: Process::Redirect::Pipe,
        output: Process::Redirect::Close,
        error: Process::Redirect::Close
      )
      handle = ProcessHandle.open(process.pid)
      group = ProcessSupervision.process_group(spec_pgid)
      child = ProcessSupervision::Child.new(process, handle, group)

      count = 12
      entered = Channel(Nil).new(count)
      results = Channel(Process::Status | Exception).new(count)
      count.times do
        spawn do
          entered.send(nil)
          begin
            results.send(child.wait.not_nil!)
          rescue ex
            results.send(ex)
          end
        end
      end
      count.times { entered.receive }
      process.input.not_nil!.puts "go"
      process.input.not_nil!.close

      outcomes = Array(Process::Status | Exception).new(count) { results.receive }
      outcomes.select(Exception).should be_empty
      statuses = outcomes.map(&.as(Process::Status))
      statuses.map(&.exit_code).should eq(Array.new(count, 23_i64))
      statuses.map(&.object_id).uniq.size.should eq(1)
      child.status.should be(statuses.first)
    ensure
      child.try &.close rescue nil
      handle.try { |value| value.close unless value.closed? } rescue nil
      process.try &.close rescue nil
      group.try &.close rescue nil
    end

    it "fans one cached child wait error out to simultaneous callers" do
      process = Process.new(
        "/bin/sh", ["-c", "sleep 30"],
        input: Process::Redirect::Close,
        output: Process::Redirect::Close,
        error: Process::Redirect::Close
      )
      handle = ProcessHandle.open(process.pid)
      group = ProcessSupervision.process_group(spec_pgid)
      child = ProcessSupervision::Child.new(process, handle, group)
      handle.close

      count = 8
      entered = Channel(Nil).new(count)
      results = Channel(Exception).new(count)
      count.times do
        spawn do
          entered.send(nil)
          begin
            child.wait
            results.send(Exception.new("wait unexpectedly succeeded"))
          rescue ex
            results.send(ex)
          end
        end
      end
      count.times { entered.receive }
      errors = Array(Exception).new(count) { results.receive }
      errors.each { |error| error.should be_a(ProcessHandle::Error::Closed) }
      errors.map(&.object_id).uniq.size.should eq(1)
    ensure
      process.try &.terminate rescue nil
      process.try &.wait rescue nil
      child.try &.close rescue nil
      handle.try { |value| value.close unless value.closed? } rescue nil
      process.try &.close rescue nil
      group.try &.close rescue nil
    end

    it "waits for a child from a raw Thread" do
      process = Process.new(
        "/bin/sh", ["-c", "sleep 0.05; exit 19"],
        input: Process::Redirect::Close,
        output: Process::Redirect::Close,
        error: Process::Redirect::Close
      )
      handle = ProcessHandle.open(process.pid)
      group = ProcessSupervision.process_group(spec_pgid)
      child = ProcessSupervision::Child.new(process, handle, group)
      result = Channel(Int64 | Exception | Nil).new(1)

      waiter = Thread.new do
        begin
          status = child.wait(2.seconds)
          result.send(status ? status.exit_code.to_i64 : nil)
        rescue ex
          result.send(ex)
        end
      end

      select
      when outcome = result.receive
        raise outcome if outcome.is_a?(Exception)
        outcome.should eq(19_i64)
      when timeout(5.seconds)
        fail "raw-thread child wait did not return"
      end
      waiter.join
    ensure
      child.try &.close rescue nil
      handle.try { |value| value.close unless value.closed? } rescue nil
      process.try &.close rescue nil
      group.try &.close rescue nil
    end

    it "runs process-group wait_empty from a raw Thread and rejects effects after close" do
      group = ProcessSupervision.process_group(spec_pgid)
      empty = Atomic(Int32).new(-1)
      waiter = Thread.new do
        begin
          empty.set(group.wait_empty(20.milliseconds) ? 1 : 0)
        rescue
          empty.set(2)
        end
      end
      waiter.join
      empty.get.should eq(0)

      group.close
      expect_raises(ProcessSupervision::Error::Closed) { group.empty? }
      expect_raises(ProcessSupervision::Error::Closed) { group.terminate }
    ensure
      group.try &.close rescue nil
    end
  end
{% end %}

describe "Windows Job cleanup source contract" do
  it "separates logical Job close from retryable completion-port cleanup" do
    job = File.read(Path[__DIR__].parent / "src/process-supervision/windows/job.cr")
    events = File.read(Path[__DIR__].parent / "src/process-supervision/windows/job/limit_events.cr")

    job.should contain("@close_lock = Thread::Mutex.new")
    job.should contain("return if @handle.null? && @events.nil?")
    job.should contain("@events = nil if @events.same?(reader)")
    job.index("Native.close_handle(@handle, \"CloseHandle(Job)\")").not_nil!.should be <
                                                                                    job.index("reader.close").not_nil!

    job.should contain("reader = @mutex.synchronize do")
    job.should contain("checked_handle\n          @events")
    events.should contain("@stopped = false")
    events.should contain("PostQueuedCompletionStatus(Job event stop)")
    events.should contain("Native.close_handle(@port, \"CloseHandle(Job event completion port)\")")
    events.should contain("@port = LibC::HANDLE.null")
    events.index("until @reader_stopped.get").not_nil!.should be <
                                                              events.index("Native.close_handle(@port, \"CloseHandle(Job event completion port)\")").not_nil!
  end
end

describe "Windows Job post-close admission source contract" do
  it "rejects hard kill and limit-event queries after close" do
    source = File.read(Path[__DIR__].parent / "src/process-supervision/windows/job.cr")

    kill_start = source.index("def kill : Nil").not_nil!
    kill_end = source.index("def close : Nil", kill_start).not_nil!
    kill_method = source[kill_start...kill_end]
    kill_method.should contain("checked_handle")
    kill_method.should_not contain("return if @handle.null?")

    events_start = source.index("def limit_events").not_nil!
    events_end = source.index("private def configure", events_start).not_nil!
    events_method = source[events_start...events_end]
    events_method.should contain("checked_handle")
  end
end

describe "Windows supervised-spawn cleanup source contract" do
  it "preserves the original setup error if stable-handle cleanup also fails" do
    source = File.read(Path[__DIR__].parent / "src/process-supervision/windows/spawn.cr")

    rescue_start = source.index("rescue ex").not_nil!
    ensure_start = source.index("ensure", rescue_start).not_nil!
    rescue_body = source[rescue_start...ensure_start]
    rescue_body.should_not contain("stable_handle.try &.close")
    rescue_body.should contain("handle.close rescue nil")
    rescue_body.index("handle.close rescue nil").not_nil!.should be <
                                                                 rescue_body.index("raise ex").not_nil!
  end
end

describe "Windows Job event-reader thread cleanup source contract" do
  it "does not use Thread#join for the dedicated completion-port reader" do
    events = File.read(Path[__DIR__].parent / "src/process-supervision/windows/job/limit_events.cr")

    events.should contain("@reader_stopped = Atomic(Bool).new(false)")
    events.should contain("until @reader_stopped.get")
    events.should_not contain("@thread.join")
  end
end

{% if flag?(:unix) %}
  private def with_temp_dir(&)
    dir = File.join(Dir.tempdir, "ps-spec-#{Process.pid}-#{Random.new.hex(4)}")
    Dir.mkdir_p(dir)
    begin
      yield dir
    ensure
      FileUtils.rm_rf(dir)
    end
  end

  private def leader(command : String, args = [] of String, **options) : ProcessSupervision::Child
    ProcessSupervision::POSIX::ProcessGroup.spawn_leader(command, args, **options)
  end

  # A child's group, wait result and local resources, released in one place.
  private def finish(child : ProcessSupervision::Child, *, timeout : Time::Span = 10.seconds) : Process::Status
    child.wait(timeout).should_not be_nil
    status = child.wait.not_nil!
    child.close
    status
  end

  describe "ProcessSupervision::POSIX::ProcessGroup spawn" do
    it "refuses process group 1, which kill(-1, sig) would turn into a broadcast" do
      expect_raises(ArgumentError, /group 1/) { ProcessSupervision.process_group(1) }
    end

    it "spawns a group leader and reports exit status, identity and its group" do
      child = leader("/bin/sh", ["-c", "exit 7"])
      group = child.group.as(ProcessSupervision::POSIX::ProcessGroup)
      group.pgid.should eq(child.pid)
      child.identity.pid.should eq(child.pid)
      status = finish(child)
      status.exit_code.should eq(7)
      child.wait.should eq(status)
      group.empty?.should be_true
      group.close
    end

    it "has the leader in its own group by the time spawn returns, and shuts the group down" do
      child = leader("/bin/sleep", ["30"])
      group = child.group.as(ProcessSupervision::POSIX::ProcessGroup)
      begin
        LibC.getpgid(child.pid.to_i32).should eq(child.pid.to_i32)
        result = group.shutdown(grace: 5.seconds, kill_after: 5.seconds)
        result.drained?.should be_true
        child.wait(10.seconds).not_nil!.exit_signal?.should eq(Signal::TERM)
      ensure
        child.close
      end
    end

    it "joins a second child to the group and ends both with one signal" do
      first = leader("/bin/sleep", ["30"])
      group = first.group.as(ProcessSupervision::POSIX::ProcessGroup)
      second = group.spawn("/bin/sleep", ["30"])
      begin
        LibC.getpgid(second.pid.to_i32).should eq(group.pgid.to_i32)
        group.empty?.should be_false
        group.shutdown(grace: 5.seconds, kill_after: 5.seconds).drained?.should be_true
        first.wait(10.seconds).should_not be_nil
        second.wait(10.seconds).should_not be_nil
      ensure
        first.close
        second.close
      end
    end

    it "passes arguments, environment and working directory to the child exactly" do
      with_temp_dir do |dir|
        output = File.join(dir, "out")
        script = %q(printf '%s|%s|%s|%s' "$1" "$2" "$FOO" "$(pwd)" > "$3")
        finish(leader("/bin/sh", ["-c", script, "sh", "a b", "", output], env: {"FOO" => "bar baz"}, chdir: dir)).success?.should be_true
        File.read(output).should eq("a b||bar baz|#{File.realpath(dir)}")
      end
    end

    it "can remove a variable and can start from an empty environment" do
      with_temp_dir do |dir|
        removed = File.join(dir, "removed")
        cleared = File.join(dir, "cleared")
        ENV["PS_SPEC_REMOVE"] = "present"
        begin
          finish(leader("/bin/sh", ["-c", %q(/usr/bin/env > "$1"), "sh", removed], env: {"PS_SPEC_REMOVE" => nil})).success?.should be_true
          finish(leader("/bin/sh", ["-c", %q(/usr/bin/env > "$1"), "sh", cleared], env: {"ONLY_THIS" => "1"}, clear_env: true)).success?.should be_true
        ensure
          ENV.delete("PS_SPEC_REMOVE")
        end
        File.read(removed).lines.none?(&.starts_with?("PS_SPEC_REMOVE=")).should be_true
        File.read(removed).lines.any?(&.starts_with?("PATH=")).should be_true
        cleared_lines = File.read(cleared).lines
        cleared_lines.should contain("ONLY_THIS=1")
        cleared_lines.none?(&.starts_with?("PATH=")).should be_true
      end
    end

    {% if flag?(:linux) %}
      it "starts the child with default signal dispositions although the runtime ignores SIGPIPE" do
        sigpipe_bit = 1_u64 << (Signal::PIPE.value - 1)
        own = File.read("/proc/self/status").lines.find!(&.starts_with?("SigIgn:")).split(':')[1].strip.to_u64(16)
        (own & sigpipe_bit).should_not eq(0) # the premise: Process.new would hand this on
        with_temp_dir do |dir|
          output = File.join(dir, "sig")
          finish(leader("/bin/sh", ["-c", %q(grep '^SigIgn:' /proc/self/status > "$1"), "sh", output])).success?.should be_true
          child_mask = File.read(output).split(':')[1].strip.to_u64(16)
          (child_mask & sigpipe_bit).should eq(0)
        end
      end

      it "leaves no descriptors and no zombies behind after many instantly exiting children" do
        before = Dir.children("/proc/self/fd").size
        50.times do
          child = leader("/bin/true")
          finish(child).success?.should be_true
          child.group.close
        end
        Dir.children("/proc/self/fd").size.should eq(before)
      end
    {% end %}

    it "raises the stdlib's exception classes for a bad command, a non-executable file and a bad directory" do
      expect_raises(File::NotFoundError) { leader("definitely-not-a-command-ps-spec") }
      expect_raises(File::NotFoundError) { leader("/bin/sh", ["-c", "true"], chdir: "/nonexistent-directory-ps-spec") }
      with_temp_dir do |dir|
        plain = File.join(dir, "plain")
        File.write(plain, "not a program")
        expect_raises(File::AccessDeniedError) { leader(plain) }
      end
    end

    it "validates its input before creating anything" do
      expect_raises(ArgumentError) { leader("") }
      expect_raises(ArgumentError) { leader("/bin/sh\0x") }
      expect_raises(ArgumentError) { leader("/bin/true", ["a\0b"]) }
      expect_raises(ArgumentError) { leader("/bin/true", env: {"A=B" => "x"}) }
      expect_raises(ArgumentError) { leader("/bin/true", env: {"A" => "x\0y"}) }
    end

    it "refuses to join a group that no longer exists" do
      first = leader("/bin/true")
      group = first.group.as(ProcessSupervision::POSIX::ProcessGroup)
      finish(first)
      expect_raises(ProcessSupervision::Error::Unavailable) { group.spawn("/bin/true") }
    end

    it "rejects spawn after the group controller is closed" do
      first = leader("/bin/true")
      group = first.group.as(ProcessSupervision::POSIX::ProcessGroup)
      finish(first)
      group.close
      expect_raises(ProcessSupervision::Error::Closed) { group.spawn("/bin/true") }
    end
  end
{% end %}

{% if flag?(:linux) %}
  private def delegated_parent_or_pending : Path
    parent = ProcessSupervision::Linux::CgroupV2.delegated_parent
    pending!("no cgroup is delegated to this process in this environment") unless parent
    parent.not_nil!
  end

  private def new_cgroup : ProcessSupervision::Linux::CgroupV2
    ProcessSupervision::Linux::CgroupV2.create(delegated_parent_or_pending, "ps-spec-#{Process.pid}-#{Random.new.hex(4)}")
  end

  private def environment_holders(token : String) : Array(Int32)
    holders = [] of Int32
    Dir.each_child("/proc") do |entry|
      next unless entry[0]?.try(&.ascii_number?)
      begin
        holders << entry.to_i if File.read("/proc/#{entry}/environ").includes?("PS_SPEC_TOKEN=#{token}")
      rescue File::Error
      end
    end
    holders
  end

  describe "ProcessSupervision::Linux::CgroupV2 spawn" do
    it "puts the child in the cgroup before it runs and sees its descendants" do
      group = new_cgroup
      child = group.spawn("/bin/sh", ["-c", "sleep 30 & sleep 30 & wait"])
      begin
        File.read("/proc/#{child.pid}/cgroup").should contain(File.basename(group.path.to_s))
        deadline = Time.instant + 5.seconds
        until File.read(group.path / "cgroup.procs").lines.size >= 3 || Time.instant > deadline
          sleep 10.milliseconds
        end
        File.read(group.path / "cgroup.procs").lines.size.should eq(3)
        group.empty?.should be_false
        group.kill
        group.wait_empty(10.seconds).should be_true
        child.wait(10.seconds).not_nil!.exit_signal?.should eq(Signal::KILL)
      ensure
        child.close
        group.kill rescue nil
        group.wait_empty(5.seconds)
        group.close
      end
    end

    it "refuses new children once the cgroup was killed" do
      group = new_cgroup
      begin
        group.kill
        expect_raises(ProcessSupervision::Error::Killed) { group.spawn("/bin/true") }
      ensure
        group.close
      end
    end

    it "uses the fork path, entering the cgroup before exec, when clone3 is refused" do
      group = new_cgroup
      ProcessSupervision::Linux::RawSpawn.clone3_disabled = true
      begin
        with_temp_dir do |dir|
          output = File.join(dir, "cgroup")
          child = group.spawn("/bin/sh", ["-c", %q(cat /proc/self/cgroup > "$1"), "sh", output])
          finish(child).success?.should be_true
          File.read(output).should contain(File.basename(group.path.to_s))
        end
      ensure
        ProcessSupervision::Linux::RawSpawn.clone3_disabled = false
        group.close
      end
    end

    it "loses no descendant: nothing survives a kill after a burst of spawns" do
      group = new_cgroup
      token = "#{Process.pid}-#{Random.new.hex(6)}"
      children = [] of ProcessSupervision::Child
      begin
        30.times do
          children << group.spawn("/bin/sh", ["-c", "sleep 60 & sleep 60 & sleep 60 & wait"], env: {"PS_SPEC_TOKEN" => token})
        end
        sleep 300.milliseconds
        group.kill
        group.wait_empty(10.seconds).should be_true
        children.each { |child| child.wait(10.seconds).should_not be_nil }
        sleep 200.milliseconds
        survivors = environment_holders(token)
        survivors.each { |pid| LibC.kill(pid, Signal::KILL.value) }
        survivors.should be_empty # a survivor was created outside the cgroup
      ensure
        children.each(&.close)
        group.close
      end
    end

    it "classifies an unusable parent as Unavailable instead of leaking a raw error" do
      expect_raises(ProcessSupervision::Error::Unavailable) do
        ProcessSupervision::Linux::CgroupV2.create("/nonexistent-cgroup-parent-ps-spec", "x")
      end
      mount = ProcessSupervision::Linux::CgroupV2.mountpoint
      pending!("no cgroup-v2 mount") unless mount
      pending!("a cgroup can be created in this environment") if ProcessSupervision::Linux::CgroupV2.delegated_parent
      # EACCES for an ordinary user, EROFS for a default container: both Unavailable, so a fallback_pgid is honoured
      expect_raises(ProcessSupervision::Error::Unavailable) do
        ProcessSupervision::Linux::CgroupV2.create(mount.not_nil!, "ps-spec-unwritable")
      end
    end

    it "reports delegated_parent consistently with usable?" do
      parent = ProcessSupervision::Linux::CgroupV2.delegated_parent
      if parent
        ProcessSupervision::Linux::CgroupV2.usable?(parent).should be_true
      else
        ProcessSupervision::Linux::CgroupV2.usable?("/nonexistent-cgroup-parent-ps-spec").should be_false
      end
    end
  end
{% end %}
