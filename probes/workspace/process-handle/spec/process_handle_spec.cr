require "./spec_helper"

{% if flag?(:linux) %}
  describe ProcessHandle do
    it "looks up and opens the current process with a stable identity" do
      identity = ProcessHandle.lookup(Process.pid).not_nil!
      identity.pid.should eq(Process.pid)
      identity.generation.should_not be_nil
      identity.alive?.should be_true

      handle = ProcessHandle.current
      begin
        handle.mechanism.should eq(ProcessHandle::Mechanism::Pidfd)
        handle.identity.same_process?(identity).should be_true
        handle.alive?.should be_true
      ensure
        handle.close
      end
    end

    it "waits for an exact child process and does not report timeout as exit" do
      child = Process.new("/bin/sh", ["-c", "sleep 0.15"])
      handle = ProcessHandle.open(child.pid)
      begin
        handle.wait(10.milliseconds).should be_false
        handle.wait(2.seconds).should be_true
        handle.identity.alive?.should be_false
      ensure
        handle.close
        child.wait
      end
    end

    it "terminates through the pidfd instead of a numeric-pid signal" do
      child = Process.new("/bin/sh", ["-c", "sleep 30"])
      handle = ProcessHandle.open(child.pid)
      begin
        handle.terminate
        handle.wait(2.seconds).should be_true
      ensure
        handle.close
        child.wait
      end
    end

    it "closes a block-scoped handle" do
      captured = nil.as(ProcessHandle?)
      ProcessHandle.open(Process.pid) do |handle|
        captured = handle
        handle.alive?.should be_true
      end
      captured.not_nil!.closed?.should be_true
    end

    it "preserves a block failure if block-scoped cleanup also fails" do
      error = expect_raises(Exception) do
        ProcessHandle.open(Process.pid) do |handle|
          linux = handle.as(ProcessHandle::Linux)
          LibC.close(linux.native_fd).should eq(0)
          raise "primary block failure"
        end
      end
      error.message.should eq("primary block failure")
    end

    it "still surfaces block-scoped cleanup failure when the block succeeds" do
      error = expect_raises(ProcessHandle::Error::Native) do
        ProcessHandle.open(Process.pid) do |handle|
          linux = handle.as(ProcessHandle::Linux)
          LibC.close(linux.native_fd).should eq(0)
        end
      end
      (error.message || "").should contain("close(pidfd)")
    end

    it "threads the real PID through pidfd signal access-denied diagnostics" do
      native = File.read(Path[__DIR__].parent / "src/process-handle/linux/native.cr")
      handle = File.read(Path[__DIR__].parent / "src/process-handle/linux/handle.cr")

      native.should contain("pidfd : IO::FileDescriptor, pid : Int64, signal : Signal")
      native.should contain("AccessDenied.new(pid, errno.message)")
      native.should_not contain("AccessDenied.new(1_i64")
      handle.should contain("Native.send_signal(pidfd, pid, signal)")
    end

    it "uses event-loop pidfd readiness rather than periodic sleep" do
      source = File.read(Path[__DIR__].parent / "src/process-handle/linux/handle.cr")
      source.should contain("Crystal::EventLoop.current.wait_readable(observed)")
      source.should_not contain("sleep({remaining, 10.milliseconds}.min)")
    end

    it "supports independent timeout and exit waits with an already-exited pidfd" do
      child = Process.new("/bin/sh", ["-c", "sleep 0.1"])
      handle = ProcessHandle.open(child.pid)
      begin
        handle.wait(Time::Span.zero).should be_false
        handle.wait(2.seconds).should be_true
        handle.wait(Time::Span.zero).should be_true
      ensure
        handle.close
        child.wait
      end
    end

    it "rejects negative wait timeouts" do
      handle = ProcessHandle.current
      begin
        expect_raises(ArgumentError) { handle.wait(-1.millisecond) }
      ensure
        handle.close
      end
    end

    it "rejects use after close" do
      handle = ProcessHandle.current
      handle.close
      expect_raises(ProcessHandle::Error::Closed) { handle.alive? }
    end

    it "treats ordinary finite Windows registered-wait timeouts as terminal without deadline re-registration" do
      source = File.read(Path[__DIR__].parent / "src/process-handle/windows/fiber_wait.cr")
      source.should contain("max_timeout = max_milliseconds.milliseconds")
      source.should contain("while remaining > max_timeout")
      source.should contain("new(process_handle, Native.registered_wait_milliseconds(remaining)).wait")
      source.should_not contain("deadline = Time.instant + timeout")
    end

    it "guards the Darwin kinfo fallback with a runtime libproc identity/layout comparison" do
      source = File.read(Path[__DIR__].parent / "src/process-handle/darwin/native.cr")
      source.should contain("elsif snapshot = kinfo_snapshot(pid)")
      source.should contain("return nil unless kinfo_layout_supported?")
      source.should contain("snapshot[1] == info.start_sec && snapshot[2] == info.start_usec")
      source.should contain("sysctl(KERN_PROC_PID)")
      source.should contain("state = present_by_signal?(pid) ? ProcessHandle::Observation::State::Unknown : ProcessHandle::Observation::State::Dead")
    end
  end
{% else %}
  describe ProcessHandle do
    it "loads the public surface" do
      ProcessHandle::VERSION.should eq("0.7.0")
    end
  end
{% end %}

{% if flag?(:darwin) %}
  describe "ProcessHandle Darwin process observation" do
    it "returns a native creation-time identity for this process" do
      observation = ProcessHandle.observe(Process.pid)
      observation.state.should eq(ProcessHandle::Observation::State::Live)
      identity = observation.identity.not_nil!
      identity.generation_known?.should be_true
      identity.same_process?(ProcessHandle.lookup(Process.pid).not_nil!).should be_true
    end

    it "does not claim that a proc_pidinfo snapshot is a stable process handle" do
      expect_raises(ProcessHandle::Error::Unsupported) { ProcessHandle.open(Process.pid) }
    end
  end
{% end %}

{% if flag?(:linux) %}
  private def build_process_handle_zombie_holder : String
    source = File.tempname("process-handle-zombie-holder", ".c")
    binary = File.tempname("process-handle-zombie-holder")
    File.write(source, <<-C)
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
  pid_t pid = fork();
  if (pid < 0) return 2;
  if (pid == 0) _exit(0);
  printf("%ld\\n", (long)pid);
  fflush(stdout);
  sleep(10);
  return 0;
}
C
    cc = ENV["CC"]? || "cc"
    status = Process.run(cc, ["-std=c99", "-O2", source, "-o", binary])
    raise "failed to build process observation zombie holder: exit #{status.exit_code}" unless status.success?
    File.delete(source) rescue nil
    binary
  end

  private def wait_for_process_observation(pid : Int64, state : ProcessHandle::Observation::State,
                                           timeout : Time::Span = 2.seconds) : ProcessHandle::Observation
    deadline = Time.instant + timeout
    loop do
      observation = ProcessHandle.observe(pid)
      return observation if observation.state == state
      raise "process #{pid} never became #{state}" if Time.instant >= deadline
      sleep 10.milliseconds
    end
  end

  describe ProcessHandle::Observation do
    it "distinguishes live, zombie, and dead process state without treating a zombie as alive" do
      ProcessHandle.observe(Process.pid).state.live?.should be_true

      binary = build_process_handle_zombie_holder
      holder = Process.new(binary, output: Process::Redirect::Pipe, error: Process::Redirect::Close)
      zombie_pid = holder.output.not_nil!.gets.not_nil!.strip.to_i64
      zombie = wait_for_process_observation(zombie_pid, ProcessHandle::Observation::State::Zombie)
      zombie.identity.should_not be_nil
      zombie.identity.not_nil!.alive?.should be_false
      zombie.terminated?.should be_true
      zombie.present?.should be_true

      holder.terminate
      holder.wait
      dead = wait_for_process_observation(zombie_pid, ProcessHandle::Observation::State::Dead)
      dead.identity.should be_nil
      dead.present?.should be_false
    ensure
      holder.try &.terminate rescue nil
      holder.try &.wait rescue nil
      holder.try &.close rescue nil
      File.delete(binary) if binary && File.exists?(binary)
    end

    it "waits from a raw Thread with no caller execution context" do
      child = Process.new("/bin/sh", ["-c", "sleep 0.05"])
      handle = ProcessHandle.open(child.pid)
      outcome = Atomic(Int32).new(0)
      waiter = Thread.new do
        begin
          outcome.set(handle.wait(2.seconds) ? 1 : 2)
        rescue
          outcome.set(3)
        end
      end
      waiter.join
      outcome.get.should eq(1)
    ensure
      handle.try { |value| value.close unless value.closed? }
      child.try &.wait rescue nil
      child.try &.close rescue nil
    end
  end
{% end %}

describe ProcessHandle::Identity do
  it "does not promote PID equality into same-process identity without generation evidence" do
    tokenless_a = ProcessHandle::Identity.new(123_i64, nil)
    tokenless_b = ProcessHandle::Identity.new(123_i64, nil)
    token_a = ProcessHandle::Identity.new(123_i64, 77_u64)
    token_b = ProcessHandle::Identity.new(123_i64, 77_u64)
    other_generation = ProcessHandle::Identity.new(123_i64, 78_u64)

    tokenless_a.same_pid?(tokenless_b).should be_true
    tokenless_a.generation_known?.should be_false
    tokenless_a.same_process?(tokenless_b).should be_false
    tokenless_a.same_process?(token_a).should be_false
    token_a.generation_known?.should be_true
    token_a.same_process?(token_b).should be_true
    token_a.same_process?(other_generation).should be_false
  end
end

describe "Windows temporary process-handle cleanup source contract" do
  it "preserves wait and operation outcomes over secondary CloseHandle failures" do
    source = File.read(Path[__DIR__].parent / "src/process-handle/windows/handle.cr")
    native = File.read(Path[__DIR__].parent / "src/process-handle/windows/native.cr")

    source.should contain("Native.close_native_handle(duplicate)")
    source.should_not contain("Native.close_handle(duplicate, \"CloseHandle(process wait duplicate)\")")
    source.should contain("Native.close_preserving_primary(handle, \"CloseHandle(process termination)\", primary)")
    source.should contain("Native.close_preserving_primary(native, \"CloseHandle(scoped native handle)\", primary)")
    native.should contain("def self.close_preserving_primary")
    native.should contain("close_native_handle(handle)")
    native.should contain("close_handle(handle, operation)")
  end
end

describe "Windows native lifecycle admission source contract" do
  it "rejects native PID overflow before DWORD conversion" do
    native = File.read(Path[__DIR__].parent / "src/process-handle/windows/native.cr")
    check = native.index("pid > UInt32::MAX").not_nil!
    conversion = native.index("pid.to_u32").not_nil!
    check.should be < conversion
  end

  it "does not reopen native capabilities after retained owner close" do
    source = File.read(Path[__DIR__].parent / "src/process-handle/windows/handle.cr")
    method_start = source.index("def with_native_handle").not_nil!
    method_end = source.index("def close", method_start).not_nil!
    method = source[method_start...method_end]

    gate = method.index("@mutex.synchronize").not_nil!
    checked = method.index("checked_handle").not_nil!
    reopen = method.index("Native.open_process").not_nil!
    gate.should be < checked
    checked.should be < reopen
  end

  it "lets the registered wait own finite timeout completion" do
    native = File.read(Path[__DIR__].parent / "src/process-handle/windows/native.cr")
    wait = File.read(Path[__DIR__].parent / "src/process-handle/windows/fiber_wait.cr")

    native.should contain("milliseconds : UInt32")
    native.should contain("handle, callback, context, milliseconds, REGISTERED_WAIT_FLAGS")
    wait.should contain("timed_out")
    wait.should contain("timed_out?")
    wait.should_not contain("@read.not_nil!.read_timeout = timeout")
  end

  it "serializes kill admission with retained owner close before reopening termination rights" do
    source = File.read(Path[__DIR__].parent / "src/process-handle/windows/handle.cr")
    method_start = source.index("def kill : Nil").not_nil!
    method_end = source.index("def with_native_handle", method_start).not_nil!
    method = source[method_start...method_end]

    gate = method.index("@mutex.synchronize").not_nil!
    checked = method.index("checked_handle").not_nil!
    reopen = method.index("Native.open_terminator").not_nil!
    gate.should be < checked
    checked.should be < reopen
  end
end
