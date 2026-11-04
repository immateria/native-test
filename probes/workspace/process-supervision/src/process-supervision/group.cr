module ProcessSupervision
  abstract class Group
    include ExecutionBridge

    struct ShutdownResult
      getter terminate_requested : Bool
      getter kill_requested : Bool
      getter drained : Bool
      getter closed : Bool

      def initialize(@terminate_requested : Bool, @kill_requested : Bool, @drained : Bool, @closed : Bool)
      end

      def terminate_requested? : Bool
        @terminate_requested
      end

      def kill_requested? : Bool
        @kill_requested
      end

      def drained? : Bool
        @drained
      end

      def closed? : Bool
        @closed
      end

      def escalated? : Bool
        @kill_requested && @terminate_requested
      end
    end

    abstract def mechanism : Mechanism
    abstract def empty? : Bool
    abstract def wait_empty(timeout : Time::Span? = nil) : Bool
    abstract def terminate : Nil
    abstract def kill : Nil
    abstract def close : Nil
    abstract def closed? : Bool
    abstract def kill_on_close? : Bool
    abstract def soft_termination? : Bool

    # Bounded terminate -> kill -> drain policy. Backends without meaningful
    # soft termination skip directly to hard kill instead of pretending that a
    # hard Windows Job termination is equivalent to SIGTERM.
    def shutdown(*, grace : Time::Span = 2.seconds, kill_after : Time::Span = 2.seconds, close : Bool = true) : ShutdownResult
      run_on_execution_context("process-supervision-group-shutdown") do
        shutdown_on_execution_context(grace: grace, kill_after: kill_after, close: close)
      end
    end

    private def shutdown_on_execution_context(*, grace : Time::Span, kill_after : Time::Span, close : Bool) : ShutdownResult
      validate_timeout(grace, "grace")
      validate_timeout(kill_after, "kill_after")

      terminate_requested = false
      kill_requested = false
      drained = false
      closed_owner = false
      primary_error = nil.as(Exception?)

      begin
        # Include the first observation in the cleanup-protected region.
        # It is itself a native operation and may fail before signalling starts.
        drained = empty?
        unless drained
          if soft_termination?
            terminate
            terminate_requested = true
            drained = wait_empty(grace)
          end
          unless drained
            kill
            kill_requested = true
            drained = wait_empty(kill_after)
          end
          unless drained
            raise Error::Timeout.new("process group did not drain after shutdown", kill_after)
          end
        end
      rescue ex
        primary_error = ex
      ensure
        if close
          begin
            self.close
            closed_owner = true
          rescue ex
            primary_error ||= ex
          end
        end
      end

      raise primary_error.not_nil! if primary_error
      ShutdownResult.new(terminate_requested, kill_requested, drained, closed_owner)
    end

    protected def validate_timeout(timeout : Time::Span?, name : String = "timeout") : Nil
      return unless timeout
      raise ArgumentError.new("#{name} must not be negative") if timeout < Time::Span.zero
    end
  end
end
