{% if flag?(:unix) %}
  module ProcessSupervision::POSIX
    # Controller for an existing POSIX process group. A process group is not a
    # kernel lifetime container: descendants can call setsid/setpgid and escape,
    # and closing this object cannot kill the group after an abrupt owner death.
    class ProcessGroup < ProcessSupervision::Group
      getter pgid : Int64

      @mutex = Thread::Mutex.new
      @closed = false

      def initialize(@pgid : Int64)
        raise ArgumentError.new("pgid must be positive") unless @pgid > 0
        raise ArgumentError.new("pgid exceeds native pid range") if @pgid > Int32::MAX
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
        @mutex.synchronize do
          check_open_locked
          group_empty_locked?
        end
      end

      def wait_empty(timeout : Time::Span? = nil) : Bool
        run_on_execution_context("process-supervision-posix-wait-empty") do
          wait_empty_on_execution_context(timeout)
        end
      end

      def terminate : Nil
        signal(Signal::TERM)
      end

      def kill : Nil
        signal(Signal::KILL)
      end

      def close : Nil
        @mutex.synchronize do
          @closed = true
        end
      end

      def closed? : Bool
        @mutex.synchronize { @closed }
      end

      private def wait_empty_on_execution_context(timeout : Time::Span?) : Bool
        validate_timeout(timeout)
        deadline = timeout.try { |span| Time.instant + span }
        loop do
          return true if empty?
          if deadline
            remaining = deadline - Time.instant
            return false if remaining <= Time::Span.zero
            sleep({remaining, 10.milliseconds}.min)
          else
            sleep 10.milliseconds
          end
        end
      end

      private def signal(signal : Signal) : Nil
        @mutex.synchronize do
          check_open_locked
          rc = LibC.kill(-@pgid.to_i32, signal.value)
          return if rc == 0
          errno = Errno.value
          return if errno == Errno::ESRCH
          raise ProcessSupervision::Error::Native.new("killpg(#{signal})", errno.message, errno.value.to_i64)
        end
      end

      private def group_empty_locked? : Bool
        rc = LibC.kill(-@pgid.to_i32, 0)
        return false if rc == 0
        errno = Errno.value
        return false if errno == Errno::EPERM
        return true if errno == Errno::ESRCH
        raise ProcessSupervision::Error::Native.new("killpg(0)", errno.message, errno.value.to_i64)
      end

      private def check_open_locked : Nil
        raise ProcessSupervision::Error::Closed.new("process group controller is closed") if @closed
      end
    end
  end
{% end %}
