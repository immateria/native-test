abstract class ProcessHandle
  getter identity : Identity

  protected def initialize(@identity : Identity)
  end

  def pid : Int64
    @identity.pid
  end

  abstract def mechanism : Mechanism
  abstract def alive? : Bool

  # Waits for this exact process identity to terminate. Returns false only when
  # a finite timeout expires first. This deliberately does not promise an exit
  # status: an arbitrary process handle may not be a waitable child on Unix.
  abstract def wait(timeout : Time::Span? = nil) : Bool

  # Requests ordinary cooperative termination where the platform provides a
  # meaningful process-level operation. Windows has no equivalent for an
  # arbitrary process HANDLE and therefore reports Unsupported.
  abstract def terminate : Nil

  # Ends the exact process identity forcefully. Idempotent after exit.
  abstract def kill : Nil

  abstract def close : Nil
  abstract def closed? : Bool

  protected def validate_timeout(timeout : Time::Span?) : Nil
    return unless timeout
    raise ArgumentError.new("timeout must not be negative") if timeout < Time::Span.zero
  end
end
