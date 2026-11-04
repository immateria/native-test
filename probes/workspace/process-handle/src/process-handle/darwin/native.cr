{% if flag?(:darwin) %}
  # ABI: xnu/bsd/sys/proc_info.h (proc_bsdinfo, PROC_PIDTBSDINFO),
  # xnu/libsyscall/wrappers/libproc/libproc.c. The whole struct must match the
  # native layout so its sizeof is validated by proc_pidinfo at runtime.
  @[Link("proc")]
  private lib LibProcessHandleDarwin
    struct BSDInfo
      flags : UInt32
      status : UInt32
      xstatus : UInt32
      pid : UInt32
      ppid : UInt32
      uid : UInt32
      gid : UInt32
      ruid : UInt32
      rgid : UInt32
      svuid : UInt32
      svgid : UInt32
      reserved : UInt32
      comm : StaticArray(UInt8, 16)
      name : StaticArray(UInt8, 32)
      nfiles : UInt32
      pgid : UInt32
      pjobc : UInt32
      tdev : UInt32
      tpgid : UInt32
      nice : Int32
      start_sec : UInt64
      start_usec : UInt64
    end

    fun proc_pidinfo(pid : Int32, flavor : Int32, arg : UInt64, info : BSDInfo*, size : Int32) : Int32
  end

  private lib LibProcessHandleDarwinSystem
    fun sysctl(name : Int32*, namelen : UInt32, oldp : Void*, oldlenp : LibC::SizeT*, newp : Void*, newlen : LibC::SizeT) : Int32
  end

  module ProcessHandle::Darwin
    private PROC_PIDTBSDINFO = 3_i32
    private SIDL             = 1_u32
    private SRUN             = 2_u32
    private SSLEEP           = 3_u32
    private SSTOP            = 4_u32
    private SZOMB            = 5_u32

    private CTL_KERN      =  1_i32
    private KERN_PROC     = 14_i32
    private KERN_PROC_PID =  1_i32

    # 64-bit Darwin extern_proc prefix offsets. These are never trusted merely
    # because they compiled: kinfo_snapshot first proves them against libproc
    # for the current process on the running kernel/SDK ABI.
    private KINFO_START_SEC_OFFSET  =  0
    private KINFO_START_USEC_OFFSET =  8
    private KINFO_STATUS_OFFSET     = 36
    private KINFO_PID_OFFSET        = 40
    private KINFO_MIN_SIZE          = KINFO_PID_OFFSET + sizeof(Int32)
    private KINFO_BUFFER_SIZE       = 4096

    # Point-in-time kernel proc snapshot; unlike a Linux pidfd or Win32 HANDLE,
    # this is NOT a retained process-control capability. In particular, a
    # subsequent kill(pid, sig) cannot be made PID-reuse-safe with this API.
    def self.observe(pid : Int64) : ProcessHandle::Observation
      if info = read_bsdinfo(pid)
        token = generation(info)
        identity = ProcessHandle::Identity.new(pid, token)
        state = case info.status
                when SZOMB
                  ProcessHandle::Observation::State::Zombie
                when SRUN, SSLEEP, SSTOP
                  token ? ProcessHandle::Observation::State::Live : ProcessHandle::Observation::State::Unknown
                when SIDL
                  ProcessHandle::Observation::State::Unknown
                else
                  # Unrecognized XNU process states cannot prove liveness.
                  ProcessHandle::Observation::State::Unknown
                end
        ProcessHandle::Observation.new(pid, state, identity)
      elsif snapshot = kinfo_snapshot(pid)
        token = snapshot_generation(snapshot)
        identity = token ? ProcessHandle::Identity.new(pid, token) : nil
        state = case snapshot[0]
                when SZOMB
                  ProcessHandle::Observation::State::Zombie
                when SRUN, SSLEEP, SSTOP
                  token ? ProcessHandle::Observation::State::Live : ProcessHandle::Observation::State::Unknown
                else
                  ProcessHandle::Observation::State::Unknown
                end
        ProcessHandle::Observation.new(pid, state, identity)
      else
        state = present_by_signal?(pid) ? ProcessHandle::Observation::State::Unknown : ProcessHandle::Observation::State::Dead
        ProcessHandle::Observation.new(pid, state, nil)
      end
    rescue ProcessHandle::Error::AccessDenied
      ProcessHandle::Observation.new(pid, ProcessHandle::Observation::State::Unknown, nil)
    end

    def self.lookup_identity(pid : Int64) : ProcessHandle::Identity?
      if info = read_bsdinfo(pid)
        ProcessHandle::Identity.new(pid, generation(info))
      elsif snapshot = kinfo_snapshot(pid)
        ProcessHandle::Identity.new(pid, snapshot_generation(snapshot))
      end
    end

    private def self.generation(info : LibProcessHandleDarwin::BSDInfo) : UInt64?
      return nil if info.start_sec == 0 || info.start_usec >= 1_000_000
      info.start_sec * 1_000_000_u64 + info.start_usec
    end

    private def self.read_bsdinfo(pid : Int64) : LibProcessHandleDarwin::BSDInfo?
      raise ArgumentError.new("pid exceeds native pid range") if pid > Int32::MAX
      unless sizeof(LibProcessHandleDarwin::BSDInfo) == 136
        raise ProcessHandle::Error::Unsupported.new("unsupported macOS proc_bsdinfo ABI layout")
      end
      info = uninitialized LibProcessHandleDarwin::BSDInfo
      Errno.value = Errno::NONE
      count = LibProcessHandleDarwin.proc_pidinfo(
        pid.to_i32, PROC_PIDTBSDINFO, 0_u64, pointerof(info), sizeof(LibProcessHandleDarwin::BSDInfo)
      )
      if count == sizeof(LibProcessHandleDarwin::BSDInfo)
        if info.pid != pid.to_u32
          raise ProcessHandle::Error::Native.new("proc_pidinfo(PROC_PIDTBSDINFO)", "returned a mismatched PID")
        end
        return info
      end
      if count > 0
        raise ProcessHandle::Error::Native.new("proc_pidinfo(PROC_PIDTBSDINFO)", "truncated proc_bsdinfo (#{count} bytes)")
      end
      errno = Errno.value
      case errno
      when Errno::ESRCH, Errno::ENOENT
        nil
      when Errno::EACCES, Errno::EPERM
        raise ProcessHandle::Error::AccessDenied.new(pid, errno.message)
      when Errno::NONE
        # libproc can report a 0-byte failure without an errno. Cross-check
        # whether the PID was removed or inspection is inconclusive.
        if present_by_signal?(pid)
          raise ProcessHandle::Error::AccessDenied.new(pid, "proc_pidinfo did not provide process identity")
        end
        nil
      else
        raise ProcessHandle::Error::Native.new(
          "proc_pidinfo(PROC_PIDTBSDINFO)", errno.message, errno.value.to_i64
        )
      end
    end

    private def self.snapshot_generation(snapshot : Tuple(UInt32, UInt64, UInt64)) : UInt64?
      start_sec = snapshot[1]
      start_usec = snapshot[2]
      return nil if start_sec == 0 || start_usec >= 1_000_000
      start_sec * 1_000_000_u64 + start_usec
    end

    # KERN_PROC_PID is a legacy snapshot surface, not a retained process handle.
    # We only use its ABI after validating the hard-coded 64-bit extern_proc
    # prefix against PROC_PIDTBSDINFO for this very process at runtime.
    private def self.kinfo_snapshot(pid : Int64) : Tuple(UInt32, UInt64, UInt64)?
      return nil unless sizeof(Void*) == 8
      return nil unless kinfo_layout_supported?
      read_kinfo_snapshot_unchecked(pid)
    end

    private def self.kinfo_layout_supported? : Bool
      self_pid = Process.pid.to_i64
      info = read_bsdinfo(self_pid)
      return false unless info
      snapshot = read_kinfo_snapshot_unchecked(self_pid)
      return false unless snapshot
      snapshot[1] == info.start_sec && snapshot[2] == info.start_usec
    rescue ProcessHandle::Error
      false
    end

    private def self.read_kinfo_snapshot_unchecked(pid : Int64) : Tuple(UInt32, UInt64, UInt64)?
      raise ArgumentError.new("pid exceeds native pid range") if pid > Int32::MAX

      mib = StaticArray(Int32, 4).new(0)
      mib[0] = CTL_KERN
      mib[1] = KERN_PROC
      mib[2] = KERN_PROC_PID
      mib[3] = pid.to_i32

      buffer = Bytes.new(KINFO_BUFFER_SIZE)
      length = LibC::SizeT.new(buffer.size)
      Errno.value = Errno::NONE
      rc = LibProcessHandleDarwinSystem.sysctl(
        mib.to_unsafe, 4_u32, buffer.to_unsafe.as(Void*), pointerof(length), Pointer(Void).null, LibC::SizeT.zero
      )
      if rc == 0
        return nil if length == 0
        if length < KINFO_MIN_SIZE
          raise ProcessHandle::Error::Native.new("sysctl(KERN_PROC_PID)", "truncated kinfo_proc (#{length} bytes)")
        end

        returned_pid = IO::ByteFormat::SystemEndian.decode(Int32, buffer[KINFO_PID_OFFSET, sizeof(Int32)])
        if returned_pid != pid
          raise ProcessHandle::Error::Native.new("sysctl(KERN_PROC_PID)", "returned a mismatched PID")
        end

        status = buffer[KINFO_STATUS_OFFSET].to_u32
        start_sec = IO::ByteFormat::SystemEndian.decode(Int64, buffer[KINFO_START_SEC_OFFSET, sizeof(Int64)])
        start_usec = IO::ByteFormat::SystemEndian.decode(Int32, buffer[KINFO_START_USEC_OFFSET, sizeof(Int32)])
        return nil if start_sec < 0 || start_usec < 0
        return {status, start_sec.to_u64, start_usec.to_u64}
      end

      errno = Errno.value
      case errno
      when Errno::ESRCH, Errno::ENOENT
        nil
      when Errno::EACCES, Errno::EPERM
        raise ProcessHandle::Error::AccessDenied.new(pid, errno.message)
      else
        raise ProcessHandle::Error::Native.new("sysctl(KERN_PROC_PID)", errno.message, errno.value.to_i64)
      end
    end

    private def self.present_by_signal?(pid : Int64) : Bool
      return true if LibC.kill(pid.to_i32, 0) == 0
      errno = Errno.value
      case errno
      when Errno::EPERM
        true
      when Errno::ESRCH
        false
      else
        raise ProcessHandle::Error::Native.new("kill(pid, 0)", errno.message, errno.value.to_i64)
      end
    end
  end
{% end %}
