module ProcessSupervision
  # Internal execution-context adapter extracted from PTY. Backends include this
  # so public waits/spawn/cleanup remain callable from raw Threads without
  # lending work to a possibly blocked default execution context.
  private module ExecutionBridge
    # Runs a spawn. With a parent-death signal it runs on `Spawner`'s thread, which lives as long as the process:
    # Linux delivers `PR_SET_PDEATHSIG` when the *thread* that created the child exits. Crystal 1.21 parks the thread
    # of a finished isolated context in a pool and ends it after `Fiber::ExecutionContext.thread_keepalive` (5
    # minutes), so a child created on such a thread was killed minutes after it started (reproduced by the spec with
    # a 50 ms keepalive).
    private def run_spawn(name : String, options : ProcessSupervision::SpawnOptions, &block : -> T) : T forall T
      if options.parent_death_signal
        Spawner.run(&block)
      else
        run_on_execution_context(name, &block)
      end
    end

    private def run_on_execution_context(name : String, &block : -> T) : T forall T
      return block.call if Fiber::ExecutionContext.current?

      lock = Thread::Mutex.new
      finished = Thread::ConditionVariable.new
      done = false
      values = [] of T
      failure = nil.as(Exception?)

      Fiber::ExecutionContext::Isolated.new(name) do
        begin
          values << block.call
        rescue ex
          failure = ex
        ensure
          lock.synchronize do
            done = true
            finished.signal
          end
        end
      end

      lock.synchronize do
        until done
          finished.wait(lock)
        end
      end

      raise failure.not_nil! if failure
      values.first
    end
  end

  # :nodoc:
  #
  # One isolated execution context that never ends, for spawns whose parent-death signal must outlive the call.
  module Spawner
    @@mutex = Thread::Mutex.new
    @@ready = Thread::ConditionVariable.new
    @@jobs = Deque(Proc(Nil)).new
    @@started = false

    def self.run(&block : -> T) : T forall T
      lock = Thread::Mutex.new
      finished = Thread::ConditionVariable.new
      done = false
      values = [] of T
      failure = nil.as(Exception?)
      job = -> do
        begin
          values << block.call
        rescue ex
          failure = ex
        ensure
          lock.synchronize do
            done = true
            finished.signal
          end
        end
        nil
      end
      @@mutex.synchronize do
        @@jobs << job
        unless @@started
          @@started = true
          Fiber::ExecutionContext::Isolated.new("process-supervision-spawner") { serve }
        end
        @@ready.signal
      end
      lock.synchronize do
        until done
          finished.wait(lock)
        end
      end
      raise failure.not_nil! if failure
      values.first
    end

    private def self.serve : Nil
      loop do
        job = @@mutex.synchronize do
          while @@jobs.empty?
            @@ready.wait(@@mutex)
          end
          @@jobs.shift
        end
        job.call
      end
    end
  end
end
