require "./process-handle/version"
require "./process-handle/error"
require "./process-handle/mechanism"
require "./process-handle/identity"
require "./process-handle/observation"
require "./process-handle/handle"
require "./process-handle/execution"

{% if flag?(:linux) %}
  require "./process-handle/linux/base"
  require "./process-handle/linux/native"
  require "./process-handle/linux/handle"
{% elsif flag?(:darwin) %}
  require "./process-handle/darwin/native"
  require "./process-handle/darwin/kqueue_handle"
{% elsif flag?(:win32) %}
  require "./process-handle/windows/base"
  require "./process-handle/windows/access"
  require "./process-handle/windows/native"
  require "./process-handle/windows/fiber_wait"
  require "./process-handle/windows/handle"
{% end %}

abstract class ProcessHandle
  def self.open(pid : Int) : ProcessHandle
    value = pid.to_i64
    {% if flag?(:linux) %}
      Linux.open(value)
    {% elsif flag?(:win32) %}
      Windows.open(value)
    {% else %}
      raise Error::Unsupported.new("stable process handles are not implemented for this target")
    {% end %}
  end

  def self.open(pid : Int, & : ProcessHandle -> T) : T forall T
    handle = open(pid)
    primary_error = nil.as(Exception?)
    begin
      yield handle
    rescue ex
      primary_error = ex
      raise ex
    ensure
      if primary_error
        handle.close rescue nil
      else
        handle.close
      end
    end
  end

  def self.current : ProcessHandle
    open(Process.pid)
  end

  # Returns a point-in-time process observation. Unlike #open this retains no
  # kernel reference and may become stale immediately. `Unknown` means the PID
  # could not be classified safely; it is not treated as live authority.
  def self.observe(pid : Int) : Observation
    value = pid.to_i64
    raise ArgumentError.new("pid must be positive") unless value > 0
    {% if flag?(:linux) %}
      Linux.observe(value)
    {% elsif flag?(:win32) %}
      Windows.observe(value)
    {% elsif flag?(:darwin) %}
      Darwin.observe(value)
    {% elsif flag?(:unix) %}
      observe_posix(value)
    {% else %}
      raise Error::Unsupported.new("process observation is not implemented for this target")
    {% end %}
  end

  # Returns a point-in-time process identity or nil if the PID is gone. Unlike
  # #open this does not retain a stable kernel reference. A caller that needs to
  # distinguish live/zombie/dead/unknown state should use `observe`.
  def self.lookup(pid : Int) : Identity?
    value = pid.to_i64
    raise ArgumentError.new("pid must be positive") unless value > 0
    {% if flag?(:linux) %}
      Linux.lookup_identity(value)
    {% elsif flag?(:win32) %}
      Windows.lookup_identity(value)
    {% elsif flag?(:darwin) %}
      Darwin.lookup_identity(value)
    {% else %}
      raise Error::Unsupported.new("process identity lookup is not implemented for this target")
    {% end %}
  rescue Error::NoSuchProcess
    nil
  end

  {% if flag?(:unix) && !flag?(:linux) %}
    # Portable existence-only fallback extracted from pty-server supervision.
    # A successful signal probe (or EPERM) proves only that a PID is present;
    # without a generation token it is deliberately Unknown, never Live.
    private def self.observe_posix(pid : Int64) : Observation
      raise ArgumentError.new("pid exceeds native pid range") if pid > Int32::MAX
      return Observation.new(pid, Observation::State::Unknown, nil) if LibC.kill(pid.to_i32, 0) == 0

      errno = Errno.value
      case errno
      when Errno::EPERM
        Observation.new(pid, Observation::State::Unknown, nil)
      when Errno::ESRCH
        Observation.new(pid, Observation::State::Dead, nil)
      else
        raise Error::Native.new("kill(pid, 0)", errno.message, errno.value.to_i64)
      end
    end
  {% end %}
end
