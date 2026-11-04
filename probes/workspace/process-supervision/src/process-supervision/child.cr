module ProcessSupervision
  # A directly spawned child plus the stable process reference and supervision
  # group that contain it. The group is externally owned; closing a Child never
  # closes the group or changes the lifetime of sibling processes.
  class Child
    include ExecutionBridge

    getter process : Process
    getter handle : ProcessHandle
    getter group : Group

    @wait_lock = Thread::Mutex.new
    @wait_in_progress = false
    @wait_error : Exception? = nil
    @wait_waiters = [] of Channel(Nil)
    @status : Process::Status? = nil

    def initialize(@process : Process, @handle : ProcessHandle, @group : Group)
    end

    def pid : Int64
      @process.pid
    end

    def identity : ProcessHandle::Identity
      @handle.identity
    end

    # Waits for this direct child and caches the exact Process::Status object.
    # Concurrent unbounded callers share one Process#wait collector, matching
    # the PTY Session contract. A finite timeout first waits on the stable
    # ProcessHandle; timeout does not start a detached collector that would keep
    # running after the caller returns.
    def wait(timeout : Time::Span? = nil) : Process::Status?
      run_on_execution_context("process-supervision-child-wait") do
        wait_on_execution_context(timeout)
      end
    end

    def status : Process::Status?
      @wait_lock.synchronize { @status }
    end

    # Closes local stream/process-wrapper and stable-handle resources only. It
    # deliberately does not close the supervision group because that group may
    # contain siblings. Cleanup attempts both owners and preserves the first
    # failure instead of leaking the second resource behind an early raise.
    def close : Nil
      run_on_execution_context("process-supervision-child-close") do
        first_error = nil.as(Exception?)
        begin
          @process.close
        rescue ex
          first_error = ex
        end

        begin
          @handle.close unless @handle.closed?
        rescue ex
          first_error ||= ex
        end

        raise first_error.not_nil! if first_error
      end
    end

    private def wait_on_execution_context(timeout : Time::Span?) : Process::Status?
      if timeout
        raise ArgumentError.new("timeout must not be negative") if timeout < Time::Span.zero
        if cached = cached_wait_outcome
          return cached
        end
        return nil unless @handle.wait(timeout)
      end

      collect_wait
    end

    private def collect_wait : Process::Status
      collector = false
      waiter = nil.as(Channel(Nil)?)

      @wait_lock.synchronize do
        if status = @status
          return status
        end
        if error = @wait_error
          raise error
        end

        if @wait_in_progress
          waiter = Channel(Nil).new(1)
          @wait_waiters << waiter.not_nil!
        else
          @wait_in_progress = true
          collector = true
        end
      end

      unless collector
        waiter.not_nil!.receive
        @wait_lock.synchronize do
          if status = @status
            return status
          end
          if error = @wait_error
            raise error
          end
        end
        raise ProcessSupervision::Error::Native.new(
          "wait", "wait collector completed without status or error"
        )
      end

      begin
        # Stable process readiness and child status remain separate authorities.
        # The handle proves this exact process terminated; Process#wait owns the
        # child's reap/status result.
        @handle.wait
        status = @process.wait
      rescue ex
        finish_wait(error: ex)
        raise ex
      else
        finish_wait(status: status)
        status
      end
    end

    private def cached_wait_outcome : Process::Status?
      @wait_lock.synchronize do
        return @status if @status
        raise @wait_error.not_nil! if @wait_error
        nil
      end
    end

    private def finish_wait(status : Process::Status? = nil, error : Exception? = nil) : Nil
      waiters = [] of Channel(Nil)
      @wait_lock.synchronize do
        @status ||= status if status
        @wait_error ||= error if error
        @wait_in_progress = false
        waiters = @wait_waiters
        @wait_waiters = [] of Channel(Nil)
      end
      waiters.each do |waiter|
        select
        when waiter.send(nil)
        else
        end
      end
    end
  end
end
