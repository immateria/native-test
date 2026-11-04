module ProcessSupervision
  # Internal execution-context adapter extracted from PTY. Backends include this
  # so public waits/spawn/cleanup remain callable from raw Threads without
  # lending work to a possibly blocked default execution context.
  private module ExecutionBridge
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
end
