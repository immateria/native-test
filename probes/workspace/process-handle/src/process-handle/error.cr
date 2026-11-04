abstract class ProcessHandle
  class Error < Exception
    class Unsupported < Error
    end

    class Closed < Error
    end

    class NoSuchProcess < Error
      getter pid : Int64

      def initialize(@pid : Int64)
        super "process #{pid} does not exist"
      end
    end

    class AccessDenied < Error
      getter pid : Int64

      def initialize(@pid : Int64, message : String = "access denied")
        super "process #{pid}: #{message}"
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
