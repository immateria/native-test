abstract class ProcessHandle
  # A process identity that survives PID reuse when the platform can provide a
  # stable generation token. The token is intentionally opaque: Linux uses
  # /proc start-time ticks while Windows uses the process creation FILETIME.
  struct Identity
    getter pid : Int64
    getter generation : UInt64?

    def initialize(@pid : Int64, @generation : UInt64?)
      raise ArgumentError.new("pid must be positive") unless @pid > 0
    end

    # Whether both identities name the same numeric PID, without making a
    # process-lifetime claim. PID equality alone is not stable identity.
    def same_pid?(other : Identity) : Bool
      pid == other.pid
    end

    # Whether this identity carries a detached generation token that can be
    # compared after the kernel handle is gone. A retained ProcessHandle may
    # still be stable even when this is false (for example a Linux pidfd when
    # /proc identity is unavailable).
    def generation_known? : Bool
      !generation.nil?
    end

    # Proves same-process identity only when both sides carry generation
    # evidence. This deliberately follows pty-server's supervision rule that
    # PID presence/equality alone is never process identity.
    def same_process?(other : Identity) : Bool
      return false unless same_pid?(other)
      mine = generation
      theirs = other.generation
      return false unless mine && theirs
      mine == theirs
    end

    # Whether this identity still names the same live process. Observation is
    # deliberately fail-closed: a zombie is terminated, and an uninspectable
    # process is `Unknown`, not optimistically treated as live.
    def alive? : Bool
      observation = ProcessHandle.observe(pid)
      return false unless observation.live?
      current = observation.identity
      return false unless current
      same_process?(current)
    end
  end
end
