module ProcessSupervision
  # A portable reading of how a process ended: a normal exit with a code, termination by a signal (or a Windows
  # Ctrl+C / Ctrl+Break exit), or a crash (a fault, an abort, a fail-fast), with a readable description that names the
  # Windows NTSTATUS where there is one.
  struct ExitOutcome
    enum Kind
      Exited
      Signaled
      Crashed
    end

    getter kind : Kind
    getter code : Int32?
    getter signal : Signal?
    getter core_dumped : Bool
    getter description : String

    def initialize(@kind : Kind, @code : Int32?, @signal : Signal?, @core_dumped : Bool, @description : String)
    end

    def crashed? : Bool
      @kind.crashed?
    end

    def success? : Bool
      @kind.exited? && @code == 0
    end

    # Names of the Windows exit statuses a supervisor sees in practice.
    NTSTATUS = {
      0xC0000005_u32 => "STATUS_ACCESS_VIOLATION",
      0xC000001D_u32 => "STATUS_ILLEGAL_INSTRUCTION",
      0xC0000094_u32 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
      0xC00000FD_u32 => "STATUS_STACK_OVERFLOW",
      0xC0000135_u32 => "STATUS_DLL_NOT_FOUND",
      0xC0000142_u32 => "STATUS_DLL_INIT_FAILED",
      0xC000013A_u32 => "STATUS_CONTROL_C_EXIT",
      0xC0000374_u32 => "STATUS_HEAP_CORRUPTION",
      0xC0000409_u32 => "STATUS_STACK_BUFFER_OVERRUN",
      0xC0000420_u32 => "STATUS_ASSERTION_FAILURE",
      0x80000003_u32 => "STATUS_BREAKPOINT",
      0x40010004_u32 => "DBG_TERMINATE_PROCESS",
    }

    def self.classify(status : ::Process::Status) : ExitOutcome
      {% if flag?(:win32) %}
        raw = status.system_exit_status.to_u32
        name = NTSTATUS[raw]?
        if raw == 0xC000013A_u32
          new(Kind::Signaled, raw.to_i32!, nil, false, "#{name} (Ctrl+C / Ctrl+Break)")
        elsif name || (raw & 0xC0000000_u32) == 0xC0000000_u32
          new(Kind::Crashed, raw.to_i32!, nil, false, name || "NTSTATUS 0x#{raw.to_s(16).upcase}")
        else
          new(Kind::Exited, raw.to_i32!, nil, false, "exited with #{raw}")
        end
      {% else %}
        if signal = status.exit_signal?
          core = (status.system_exit_status & 0x80) != 0
          crash = status.exit_reason.in?(::Process::ExitReason::AccessViolation, ::Process::ExitReason::BadMemoryAccess,
            ::Process::ExitReason::BadInstruction, ::Process::ExitReason::FloatException,
            ::Process::ExitReason::Aborted, ::Process::ExitReason::Breakpoint)
          text = "killed by #{signal}#{core ? " (core dumped)" : ""}"
          new(crash ? Kind::Crashed : Kind::Signaled, nil, signal, core, text)
        else
          code = status.exit_code
          new(Kind::Exited, code, nil, false, "exited with #{code}")
        end
      {% end %}
    end
  end
end
