abstract class ProcessHandle
  # A point-in-time observation of one PID. This is deliberately distinct from
  # a retained ProcessHandle: an observation can become stale immediately.
  #
  # `Unknown` means the PID may exist but this process could not prove a live
  # identity. Treat it as uncertainty, never as `Live` or `Dead` authority.
  struct Observation
    enum State
      Dead
      Zombie
      Live
      Unknown
    end

    getter pid : Int64
    getter state : State
    getter identity : Identity?

    def initialize(@pid : Int64, @state : State, @identity : Identity?)
      raise ArgumentError.new("pid must be positive") unless @pid > 0
    end

    def live? : Bool
      @state.live?
    end

    def terminated? : Bool
      @state.dead? || @state.zombie?
    end

    def present? : Bool
      !@state.dead?
    end
  end
end
