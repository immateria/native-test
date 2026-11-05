abstract class ProcessHandle
  # A point-in-time resource reading for one process. Fields a platform cannot provide are nil. Times are CPU time
  # consumed so far; memory in bytes (normalised: Linux reports KiB, macOS bytes); I/O in bytes actually read from and
  # written to storage where the OS counts that, else transferred bytes (Windows).
  record Usage,
    user_time : Time::Span,
    system_time : Time::Span,
    resident_bytes : UInt64?,
    peak_resident_bytes : UInt64?,
    read_bytes : UInt64?,
    written_bytes : UInt64? do
    def cpu_time : Time::Span
      user_time + system_time
    end
  end

  # Sends *signal* to this exact process. Backends that cannot deliver POSIX signals raise `Error::Unsupported`.
  def signal(signal : Signal) : Nil
    raise Error::Unsupported.new("#{mechanism} handles cannot deliver #{signal}")
  end

  # Stops the process from running (SIGSTOP; on Windows every thread is suspended) until `resume`.
  def suspend : Nil
    {% if flag?(:unix) %}
      signal(Signal::STOP)
    {% else %}
      raise Error::Unsupported.new("suspend is not implemented for #{mechanism}")
    {% end %}
  end

  def resume : Nil
    {% if flag?(:unix) %}
      signal(Signal::CONT)
    {% else %}
      raise Error::Unsupported.new("resume is not implemented for #{mechanism}")
    {% end %}
  end

  # Current resource usage of this process. Linux and macOS can read it only while the process exists (a zombie
  # included); Windows also after it has exited, as long as this handle is open.
  def usage : Usage
    {% if flag?(:linux) %}
      ProcessHandle::UsageReader.linux(pid)
    {% elsif flag?(:darwin) %}
      ProcessHandle::UsageReader.darwin(pid)
    {% else %}
      raise Error::Unsupported.new("usage is not implemented for #{mechanism}")
    {% end %}
  end
end

{% if flag?(:darwin) %}
  @[Link("proc")]
  private lib LibProcessHandleUsage
    fun proc_pid_rusage(pid : Int32, flavor : Int32, buffer : Void*) : Int32
    fun mach_timebase_info(info : UInt32*) : Int32
  end
{% end %}

# :nodoc:
module ProcessHandle::UsageReader
  {% if flag?(:linux) %}
    @@ticks : Int64? = nil

    def self.linux(pid : Int64) : ProcessHandle::Usage
      stat = read("/proc/#{pid}/stat", pid)
      # the command name may contain spaces and parentheses: fields start after the last ')'
      fields = stat[(stat.rindex(')') || raise ProcessHandle::Error::NoSuchProcess.new(pid)) + 2..].split(' ')
      ticks = (@@ticks ||= LibC.sysconf(LibC::SC_CLK_TCK).to_i64.clamp(1_i64, Int64::MAX))
      user = fields[11].to_i64
      system = fields[12].to_i64
      status = read("/proc/#{pid}/status", pid)
      resident = kib(status, "VmRSS:")
      peak = kib(status, "VmHWM:")
      read_bytes = written = nil.as(UInt64?)
      begin
        io = File.read("/proc/#{pid}/io")
        read_bytes = field(io, "read_bytes:")
        written = field(io, "write_bytes:")
      rescue File::Error
        # /proc/<pid>/io needs ptrace access (a zombie answers EACCES)
      end
      ProcessHandle::Usage.new(
        user_time: (user * 1_000_000_000 // ticks).nanoseconds,
        system_time: (system * 1_000_000_000 // ticks).nanoseconds,
        resident_bytes: resident, peak_resident_bytes: peak, read_bytes: read_bytes, written_bytes: written)
    end

    private def self.read(path : String, pid : Int64) : String
      File.read(path)
    rescue File::NotFoundError
      raise ProcessHandle::Error::NoSuchProcess.new(pid)
    end

    private def self.kib(text : String, key : String) : UInt64?
      field(text, key).try &.*(1024_u64)
    end

    private def self.field(text : String, key : String) : UInt64?
      text.each_line do |line|
        next unless line.starts_with?(key)
        return line[key.size..].strip.split(' ').first.to_u64?
      end
      nil
    end
  {% end %}

  {% if flag?(:darwin) %}
    private RUSAGE_INFO_V4 = 4

    # rusage_info_v4 offsets (xnu bsd/sys/resource.h): user 16, system 24, resident 64, disk read 144, written 152,
    # lifetime max footprint 240. CPU times are mach absolute time units, converted with the timebase.
    def self.darwin(pid : Int64) : ProcessHandle::Usage
      buffer = Bytes.new(512)
      if LibProcessHandleUsage.proc_pid_rusage(pid.to_i32, RUSAGE_INFO_V4, buffer.to_unsafe.as(Void*)) != 0
        errno = Errno.value
        raise ProcessHandle::Error::NoSuchProcess.new(pid) if errno == Errno::ESRCH
        raise ProcessHandle::Error::Native.new("proc_pid_rusage", errno.message, errno.value.to_i64)
      end
      at = ->(offset : Int32) { (buffer.to_unsafe + offset).as(UInt64*).value }
      timebase = StaticArray(UInt32, 2).new(1_u32)
      LibProcessHandleUsage.mach_timebase_info(timebase.to_unsafe)
      to_span = ->(ticks : UInt64) { (ticks.to_u128 * timebase[0] // timebase[1]).to_i64.nanoseconds }
      ProcessHandle::Usage.new(
        user_time: to_span.call(at.call(16)), system_time: to_span.call(at.call(24)),
        resident_bytes: at.call(64), peak_resident_bytes: at.call(240),
        read_bytes: at.call(144), written_bytes: at.call(152))
    end
  {% end %}
end
