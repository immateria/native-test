module ProcessSupervision
  class Error < Exception
    class Unsupported < Error
    end

    class Closed < Error
    end

    class Busy < Error
    end

    # The group was killed and cannot take new children (a cgroup written cgroup.kill kills every process later cloned
    # into it, measured on kernels 6.8, 7.0 and 6.18). Create a new group.
    class Killed < Error
    end

    class Unavailable < Error
    end

    class Timeout < Error
      getter timeout : Time::Span

      def initialize(message : String, @timeout : Time::Span)
        super "#{message} (timeout=#{timeout})"
      end
    end

    class Native < Error
      getter operation : String
      getter native_code : Int64?

      def initialize(@operation : String, message : String, @native_code : Int64? = nil)
        suffix = @native_code ? " (native=#{@native_code})" : ""
        super "#{operation}: #{message}#{suffix}"
      end
    end
  end
end
