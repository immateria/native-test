require "./spec_helper"

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
      group = ProcessSupervision.process_group(Process.pgid)
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

    it "never opens the hierarchy root as a killable supervision group" do
      if mount = ProcessSupervision::Linux::CgroupV2.mountpoint
        expect_raises(ArgumentError, /hierarchy root/) do
          ProcessSupervision::Linux::CgroupV2.open(mount)
        end
      end
    end

    it "makes a weaker process-group fallback observable" do
      missing = Path["/definitely-missing-process-supervision-cgroup"]
      group = ProcessSupervision.cgroup_v2(missing, fallback_pgid: Process.pgid)
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
      group = ProcessSupervision.process_group(Process.pgid)
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
      group = ProcessSupervision.process_group(Process.pgid)
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
      group = ProcessSupervision.process_group(Process.pgid)
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
      group = ProcessSupervision.process_group(Process.pgid)
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
      group = ProcessSupervision.process_group(Process.pgid)
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
