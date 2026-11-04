{% if flag?(:win32) %}
  module ProcessSupervision::Windows
    class Job
      enum PriorityClass : UInt32
        Idle        = 0x00000040
        BelowNormal = 0x00004000
        Normal      = 0x00000020
        AboveNormal = 0x00008000
        High        = 0x00000080
      end

      @[Flags]
      enum UIRestrictions : UInt32
        Handles          = 0x0001
        ReadClipboard    = 0x0002
        WriteClipboard   = 0x0004
        SystemParameters = 0x0008
        DisplaySettings  = 0x0010
        GlobalAtoms      = 0x0020
        Desktop          = 0x0040
        ExitWindows      = 0x0080
      end

      record Limits,
        job_memory : UInt64? = nil,
        process_memory : UInt64? = nil,
        active_processes : UInt32? = nil,
        job_user_time : Time::Span? = nil,
        process_user_time : Time::Span? = nil,
        cpu_rate_percent : Float64? = nil,
        priority_class : PriorityClass? = nil,
        ui_restrictions : UIRestrictions? = nil do
        def validate! : Nil
          {job_memory: job_memory, process_memory: process_memory}.each do |name, value|
            next unless value
            raise ArgumentError.new("#{name} must be positive") unless value > 0
          end
          if (count = active_processes) && count == 0
            raise ArgumentError.new("active_processes must be positive")
          end
          {job_user_time: job_user_time, process_user_time: process_user_time}.each do |name, value|
            next unless value
            raise ArgumentError.new("#{name} must be positive") unless value > Time::Span.zero
          end
          if percent = cpu_rate_percent
            unless percent > 0 && percent <= 100 && (percent * 100).round >= 1
              raise ArgumentError.new("cpu_rate_percent must be greater than 0 and at most 100")
            end
          end
        end
      end
    end
  end
{% end %}
