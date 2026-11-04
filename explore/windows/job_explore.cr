# Windows Job-object exploration. Standalone: it records what the OS does as JSON
# lines on stdout and never asserts. Each experiment answers a question the
# qualification kit raised but could not settle:
#
#   token            who are we? elevated? integrity level? which privileges, enabled or not?
#   priority         which job priority classes does SetInformationJobObject accept, and does
#                    enabling SeIncreaseBasePriorityPrivilege change that?
#   cpu-time         how long after the limit is crossed does Windows kill a CPU-spinning
#                    child, and is enforcement reliable? (repeated trials, per-trial timing)
#   notify           when does JOB_OBJECT_MSG_NOTIFICATION_LIMIT / the violation query fire
#                    for write-bytes, read-bytes and job-time notification limits?
#   launch-unelevated -- <cmd...>
#                    run <cmd> with a UAC-style filtered token (LUA_TOKEN, privileges stripped,
#                    Medium integrity) so the kit's "never elevate" rule can be honoured from an
#                    elevated CI session.
#
# Compile (Windows only): crystal build job_explore.cr -o job_explore.exe
require "json"

{% unless flag?(:win32) %}
  {% raise "job_explore.cr must be compiled for Windows" %}
{% end %}

@[Link("kernel32")]
@[Link("advapi32")]
lib WX
  struct JobNotificationLimit
    io_read_bytes_limit : UInt64
    io_write_bytes_limit : UInt64
    per_job_user_time_limit : Int64
    job_memory_limit : UInt64
    rate_control_tolerance : Int32
    rate_control_tolerance_interval : Int32
    limit_flags : UInt32
  end

  struct JobLimitViolation
    limit_flags : UInt32
    violation_limit_flags : UInt32
    io_read_bytes : UInt64
    io_read_bytes_limit : UInt64
    io_write_bytes : UInt64
    io_write_bytes_limit : UInt64
    per_job_user_time : Int64
    per_job_user_time_limit : Int64
    job_memory : UInt64
    job_memory_limit : UInt64
    rate_control_tolerance : Int32
    rate_control_tolerance_limit : Int32
  end

  struct BasicAccounting
    total_user_time : Int64
    total_kernel_time : Int64
    this_period_user_time : Int64
    this_period_kernel_time : Int64
    page_fault_count : UInt32
    total_processes : UInt32
    active_processes : UInt32
    total_terminated_processes : UInt32
  end

  struct BasicAndIoAccounting
    basic : BasicAccounting
    io : LibC::IO_COUNTERS
  end

  # TOKEN_PRIVILEGES with exactly one LUID_AND_ATTRIBUTES entry.
  struct TokenPrivilege1
    count : UInt32
    luid_low : UInt32
    luid_high : Int32
    attributes : UInt32
  end

  struct SidAndAttributes
    sid : Void*
    attributes : UInt32
  end

  fun QueryInformationJobObject(job : LibC::HANDLE, info_class : UInt32, info : Void*, length : UInt32, return_length : UInt32*) : LibC::BOOL
  fun IsProcessInJob(process : LibC::HANDLE, job : LibC::HANDLE, result : LibC::BOOL*) : LibC::BOOL
  fun GetCurrentProcess : LibC::HANDLE
  fun GetPriorityClass(process : LibC::HANDLE) : UInt32
  fun SetPriorityClass(process : LibC::HANDLE, priority_class : UInt32) : LibC::BOOL
  fun OpenProcessToken(process : LibC::HANDLE, access : UInt32, token : LibC::HANDLE*) : LibC::BOOL
  fun GetTokenInformation(token : LibC::HANDLE, info_class : UInt32, info : Void*, length : UInt32, return_length : UInt32*) : LibC::BOOL
  fun SetTokenInformation(token : LibC::HANDLE, info_class : UInt32, info : Void*, length : UInt32) : LibC::BOOL
  fun LookupPrivilegeValueW(system_name : UInt16*, name : UInt16*, luid : UInt64*) : LibC::BOOL
  fun LookupPrivilegeNameW(system_name : UInt16*, luid : UInt64*, name : UInt16*, length : UInt32*) : LibC::BOOL
  fun AdjustTokenPrivileges(token : LibC::HANDLE, disable_all : LibC::BOOL, new_state : Void*, buffer_length : UInt32, previous_state : Void*, return_length : UInt32*) : LibC::BOOL
  fun CheckTokenMembership(token : LibC::HANDLE, sid : Void*, is_member : LibC::BOOL*) : LibC::BOOL
  fun SetHandleInformation(handle : LibC::HANDLE, mask : UInt32, flags : UInt32) : LibC::BOOL
  fun CreateWellKnownSid(sid_type : Int32, domain_sid : Void*, sid : Void*, size : UInt32*) : LibC::BOOL
  fun CreateRestrictedToken(existing : LibC::HANDLE, flags : UInt32, disable_count : UInt32, disable_sids : Void*,
                            delete_count : UInt32, delete_privs : Void*, restrict_count : UInt32, restrict_sids : Void*,
                            new_token : LibC::HANDLE*) : LibC::BOOL
  fun GetLengthSid(sid : Void*) : UInt32
  fun CreateProcessAsUserW(token : LibC::HANDLE, application : UInt16*, command_line : UInt16*,
                           process_attrs : LibC::SECURITY_ATTRIBUTES*, thread_attrs : LibC::SECURITY_ATTRIBUTES*,
                           inherit_handles : LibC::BOOL, creation_flags : UInt32, environment : Void*,
                           current_directory : UInt16*, startup : LibC::STARTUPINFOW*, info : LibC::PROCESS_INFORMATION*) : LibC::BOOL
end

module Explore
  INVALID_HANDLE_VALUE = Pointer(Void).new(UInt64::MAX)
  CREATE_SUSPENDED     = 0x00000004_u32
  WAIT_OBJECT_0        = 0_u32

  JOB_OBJECT_LIMIT_PROCESS_TIME     = 0x00000002_u32
  JOB_OBJECT_LIMIT_JOB_TIME         = 0x00000004_u32
  JOB_OBJECT_LIMIT_PRIORITY_CLASS   = 0x00000020_u32
  JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000_u32
  JOB_OBJECT_LIMIT_JOB_READ_BYTES   = 0x00010000_u32
  JOB_OBJECT_LIMIT_JOB_WRITE_BYTES  = 0x00020000_u32

  CLASS_BASIC_ACCOUNTING   =  1
  CLASS_BASIC_LIMIT        =  2
  CLASS_BASIC_IO_ACCOUNTING = 8
  CLASS_EXTENDED_LIMIT     =  9
  CLASS_NOTIFICATION_LIMIT = 12
  CLASS_LIMIT_VIOLATION    = 13

  PRIORITY_CLASSES = {
    "idle"         => 0x00000040_u32,
    "below_normal" => 0x00004000_u32,
    "normal"       => 0x00000020_u32,
    "above_normal" => 0x00008000_u32,
    "high"         => 0x00000080_u32,
    "realtime"     => 0x00000100_u32,
  }

  def self.exe : String
    Process.executable_path || raise "no executable path"
  end

  def self.tmpdir : String
    ENV["EXPLORE_TMP"]? || Dir.tempdir
  end

  def self.emit(kind : String, &)
    line = JSON.build do |j|
      j.object do
        j.field "kind", kind
        j.field "at", Time.utc.to_s("%FT%T.%3NZ")
        yield j
      end
    end
    puts line
    STDOUT.flush
  end

  def self.wide(text : String) : Slice(UInt16)
    text.to_utf16
  end

  # --- jobs and processes ---------------------------------------------------

  def self.new_job : LibC::HANDLE
    job = LibC.CreateJobObjectW(Pointer(LibC::SECURITY_ATTRIBUTES).null, Pointer(UInt16).null)
    raise "CreateJobObjectW failed: #{LibC.GetLastError}" if job.null?
    job
  end

  def self.associate_port(job : LibC::HANDLE, key : UInt64) : LibC::HANDLE
    port = LibC.CreateIoCompletionPort(INVALID_HANDLE_VALUE, LibC::HANDLE.null, Pointer(LibC::ULong).null, 1_u32)
    raise "CreateIoCompletionPort failed: #{LibC.GetLastError}" if port.null?
    assoc = LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT.new(completionKey: Pointer(Void).new(key), completionPort: port)
    rc = LibC.SetInformationJobObject(job, LibC::JOBOBJECTINFOCLASS::AssociateCompletionPortInformation,
      pointerof(assoc).as(Void*), sizeof(LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT).to_u32)
    raise "associate completion port failed: #{LibC.GetLastError}" if rc == 0
    port
  end

  # {message, milliseconds since `since`}
  def self.drain(port : LibC::HANDLE, since : Time::Instant, into : Array({UInt32, Float64})) : Nil
    loop do
      entry = LibC::OVERLAPPED_ENTRY.new
      removed = LibC::ULong.new(0)
      rc = LibC.GetQueuedCompletionStatusEx(port, pointerof(entry), 1, pointerof(removed), 0_u32, 0)
      break if rc == 0 || removed == 0
      into << {entry.dwNumberOfBytesTransferred, (Time.instant - since).total_milliseconds}
    end
  end

  def self.spawn_suspended(args : Array(String)) : {LibC::HANDLE, LibC::HANDLE, UInt32}
    command_line = Process.quote_windows(args).to_utf16
    startup = LibC::STARTUPINFOW.new
    startup.cb = sizeof(LibC::STARTUPINFOW).to_u32
    info = LibC::PROCESS_INFORMATION.new
    rc = LibC.CreateProcessW(Pointer(UInt16).null, command_line.to_unsafe,
      Pointer(LibC::SECURITY_ATTRIBUTES).null, Pointer(LibC::SECURITY_ATTRIBUTES).null,
      0, CREATE_SUSPENDED, Pointer(Void).null, Pointer(UInt16).null,
      pointerof(startup), pointerof(info))
    raise "CreateProcessW failed: #{LibC.GetLastError}" if rc == 0
    {info.hProcess, info.hThread, info.dwProcessId}
  end

  # Spawn `args` suspended, put it in `job`, resume it. Returns {process, pid}.
  def self.start_in_job(job : LibC::HANDLE, args : Array(String)) : {LibC::HANDLE, UInt32}
    process, thread, pid = spawn_suspended(args)
    if LibC.AssignProcessToJobObject(job, process) == 0
      err = LibC.GetLastError
      LibC.TerminateProcess(process, 99_u32)
      raise "AssignProcessToJobObject failed: #{err}"
    end
    LibC.ResumeThread(thread)
    LibC.CloseHandle(thread)
    {process, pid}
  end

  def self.process_done?(process : LibC::HANDLE) : Bool
    LibC.WaitForSingleObject(process, 0_u32) == WAIT_OBJECT_0
  end

  def self.exit_code(process : LibC::HANDLE) : UInt32
    code = 0_u32
    LibC.GetExitCodeProcess(process, pointerof(code))
    code
  end

  def self.filetime_ms(ft : LibC::FILETIME) : Float64
    ((ft.dwHighDateTime.to_u64 << 32) | ft.dwLowDateTime.to_u64).to_f64 / 10_000.0
  end

  # user-mode CPU milliseconds consumed by a (finished or running) process
  def self.process_user_ms(process : LibC::HANDLE) : Float64
    creation = LibC::FILETIME.new
    exit_t = LibC::FILETIME.new
    kernel = LibC::FILETIME.new
    user = LibC::FILETIME.new
    LibC.GetProcessTimes(process, pointerof(creation), pointerof(exit_t), pointerof(kernel), pointerof(user)) == 0 ? -1.0 : filetime_ms(user)
  end

  def self.query_basic_accounting(job : LibC::HANDLE) : WX::BasicAccounting?
    info = WX::BasicAccounting.new
    returned = 0_u32
    rc = WX.QueryInformationJobObject(job, CLASS_BASIC_ACCOUNTING.to_u32, pointerof(info).as(Void*), sizeof(WX::BasicAccounting).to_u32, pointerof(returned))
    rc == 0 ? nil : info
  end

  def self.query_io_accounting(job : LibC::HANDLE) : WX::BasicAndIoAccounting?
    info = WX::BasicAndIoAccounting.new
    returned = 0_u32
    rc = WX.QueryInformationJobObject(job, CLASS_BASIC_IO_ACCOUNTING.to_u32, pointerof(info).as(Void*), sizeof(WX::BasicAndIoAccounting).to_u32, pointerof(returned))
    rc == 0 ? nil : info
  end

  def self.query_violation(job : LibC::HANDLE) : {Bool, UInt32, WX::JobLimitViolation}
    info = WX::JobLimitViolation.new
    returned = 0_u32
    rc = WX.QueryInformationJobObject(job, CLASS_LIMIT_VIOLATION.to_u32, pointerof(info).as(Void*), sizeof(WX::JobLimitViolation).to_u32, pointerof(returned))
    {rc != 0, rc == 0 ? LibC.GetLastError : 0_u32, info}
  end

  def self.set_job_info(job : LibC::HANDLE, info_class : Int32, info : Void*, size : Int) : {Bool, UInt32}
    rc = LibC.SetInformationJobObject(job, LibC::JOBOBJECTINFOCLASS.new(info_class), info, size.to_u32)
    {rc != 0, rc == 0 ? LibC.GetLastError : 0_u32}
  end

  def self.cleanup(process : LibC::HANDLE?, job : LibC::HANDLE?, port : LibC::HANDLE? = nil) : Nil
    if process
      LibC.TerminateProcess(process, 98_u32) unless process_done?(process)
      LibC.WaitForSingleObject(process, 2000_u32)
      LibC.CloseHandle(process)
    end
    LibC.CloseHandle(job) if job
    LibC.CloseHandle(port) if port
  end

  # --- token ---------------------------------------------------------------

  def self.open_token(access : UInt32) : LibC::HANDLE
    token = LibC::HANDLE.null
    raise "OpenProcessToken failed: #{LibC.GetLastError}" if WX.OpenProcessToken(WX.GetCurrentProcess, access, pointerof(token)) == 0
    token
  end

  def self.token_u32(token : LibC::HANDLE, info_class : UInt32) : UInt32?
    value = 0_u32
    returned = 0_u32
    WX.GetTokenInformation(token, info_class, pointerof(value).as(Void*), 4_u32, pointerof(returned)) == 0 ? nil : value
  end

  def self.privilege_name(luid : UInt64) : String
    buffer = Slice(UInt16).new(128)
    length = 128_u32
    local = luid
    return "luid:#{luid}" if WX.LookupPrivilegeNameW(Pointer(UInt16).null, pointerof(local), buffer.to_unsafe, pointerof(length)) == 0
    String.from_utf16(buffer[0, length.to_i])
  end

  def self.exp_token : Nil
    token = open_token(0x0008_u32) # TOKEN_QUERY
    elevated = token_u32(token, 20_u32)      # TokenElevation
    elevation_type = token_u32(token, 18_u32) # 1 default, 2 full (elevated), 3 limited (filtered)

    integrity = -1_i64
    buffer = Slice(UInt8).new(256)
    returned = 0_u32
    if WX.GetTokenInformation(token, 25_u32, buffer.to_unsafe.as(Void*), 256_u32, pointerof(returned)) != 0
      sid = buffer.to_unsafe.as(Pointer(Pointer(UInt8))).value
      count = sid[1]
      integrity = (sid + 8 + 4 * (count.to_i - 1)).as(Pointer(UInt32)).value.to_i64
    end

    privileges = [] of {String, UInt32}
    big = Slice(UInt8).new(4096)
    if WX.GetTokenInformation(token, 3_u32, big.to_unsafe.as(Void*), 4096_u32, pointerof(returned)) != 0
      n = big.to_unsafe.as(Pointer(UInt32)).value
      n.times do |i|
        entry = big.to_unsafe + 4 + 12 * i
        low = entry.as(Pointer(UInt32)).value
        high = (entry + 4).as(Pointer(Int32)).value
        attrs = (entry + 8).as(Pointer(UInt32)).value
        privileges << {privilege_name((high.to_u64 << 32) | low.to_u64), attrs}
      end
    end

    admin_sid = Slice(UInt8).new(68)
    size = 68_u32
    in_admins = -1
    if WX.CreateWellKnownSid(26, Pointer(Void).null, admin_sid.to_unsafe.as(Void*), pointerof(size)) != 0
      member = 0
      in_admins = WX.CheckTokenMembership(LibC::HANDLE.null, admin_sid.to_unsafe.as(Void*), pointerof(member)) != 0 ? member : -1
    end

    in_job = 0
    WX.IsProcessInJob(WX.GetCurrentProcess, LibC::HANDLE.null, pointerof(in_job))

    emit("token") do |j|
      j.field "user", "#{ENV["USERDOMAIN"]?}\\#{ENV["USERNAME"]?}"
      j.field "token_is_elevated", elevated.try(&.to_i) || -1
      j.field "elevation_type", elevation_type.try(&.to_i) || -1
      j.field "integrity_rid_hex", integrity < 0 ? "unknown" : "0x#{integrity.to_s(16)}"
      j.field "administrators_group_enabled", in_admins
      j.field "process_in_job", in_job
      j.field "priority_class_self_hex", "0x#{WX.GetPriorityClass(WX.GetCurrentProcess).to_s(16)}"
      j.field "privileges" do
        j.array do
          privileges.each do |name, attrs|
            j.object do
              j.field "name", name
              j.field "enabled", (attrs & 0x2_u32) != 0
              j.field "attributes_hex", "0x#{attrs.to_s(16)}"
            end
          end
        end
      end
    end
    LibC.CloseHandle(token)
  end

  # --- privilege enable ----------------------------------------------------

  def self.enable_privilege(name : String) : {Bool, UInt32}
    token = LibC::HANDLE.null
    if WX.OpenProcessToken(WX.GetCurrentProcess, 0x0028_u32, pointerof(token)) == 0 # ADJUST_PRIVILEGES | QUERY
      return {false, LibC.GetLastError}
    end
    luid = 0_u64
    return {false, LibC.GetLastError} if WX.LookupPrivilegeValueW(Pointer(UInt16).null, wide(name).to_unsafe, pointerof(luid)) == 0
    state = WX::TokenPrivilege1.new
    state.count = 1_u32
    state.luid_low = (luid & 0xffff_ffff_u64).to_u32
    state.luid_high = (luid >> 32).to_i32
    state.attributes = 0x2_u32 # SE_PRIVILEGE_ENABLED
    WX.AdjustTokenPrivileges(token, 0, pointerof(state).as(Void*), 0_u32, Pointer(Void).null, Pointer(UInt32).null)
    err = LibC.GetLastError # 0 = adjusted, 1300 = ERROR_NOT_ALL_ASSIGNED (privilege not held)
    LibC.CloseHandle(token)
    {err == 0_u32, err}
  end

  # --- priority --------------------------------------------------------------

  def self.exp_priority : Nil
    ["before_enable", "after_enable"].each do |phase|
      if phase == "after_enable"
        ok, err = enable_privilege("SeIncreaseBasePriorityPrivilege")
        emit("priority_enable_privilege") { |j| j.field "adjusted", ok; j.field "last_error", err }
      end
      PRIORITY_CLASSES.each do |name, value|
        # {info class, extra limit flags}: basic, extended, and extended + KILL_ON_JOB_CLOSE (what the kit sends)
        [{CLASS_BASIC_LIMIT, 0_u32}, {CLASS_EXTENDED_LIMIT, 0_u32}, {CLASS_EXTENDED_LIMIT, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE}].each do |info_class, extra|
          job = new_job
          process = nil.as(LibC::HANDLE?)
          begin
            if info_class == CLASS_BASIC_LIMIT
              info = LibC::JOBOBJECT_BASIC_LIMIT_INFORMATION.new
              info.limitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS | extra
              info.priorityClass = value
              ok, err = set_job_info(job, info_class, pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_BASIC_LIMIT_INFORMATION))
            else
              info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
              info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS | extra
              info.basicLimitInformation.priorityClass = value
              ok, err = set_job_info(job, info_class, pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION))
            end
            before = -1_i64
            after_assign = -1_i64
            applied = -1_i64
            if ok
              proc, thread, _pid = spawn_suspended([exe, "child-sleep", "400"])
              process = proc
              before = WX.GetPriorityClass(proc).to_i64
              raise "assign failed: #{LibC.GetLastError}" if LibC.AssignProcessToJobObject(job, proc) == 0
              after_assign = WX.GetPriorityClass(proc).to_i64
              LibC.ResumeThread(thread)
              LibC.CloseHandle(thread)
              sleep 50.milliseconds
              applied = WX.GetPriorityClass(proc).to_i64
            end
            hex = ->(v : Int64) { v < 0 ? "none" : "0x#{v.to_s(16)}" }
            emit("priority_job") do |j|
              j.field "phase", phase
              j.field "class", name
              j.field "info_class", info_class
              j.field "extra_flags_hex", "0x#{extra.to_s(16)}"
              j.field "set_ok", ok
              j.field "set_error", err
              j.field "child_before_assign_hex", hex.call(before)
              j.field "child_after_assign_hex", hex.call(after_assign)
              j.field "child_priority_hex", hex.call(applied)
            end
          rescue ex
            emit("priority_job_error") { |j| j.field "phase", phase; j.field "class", name; j.field "error", ex.message || ex.class.name }
          ensure
            cleanup(process, job)
          end
        end
        # same class without a job, for comparison
        original = WX.GetPriorityClass(WX.GetCurrentProcess)
        rc = WX.SetPriorityClass(WX.GetCurrentProcess, value)
        err = rc == 0 ? LibC.GetLastError : 0_u32
        WX.SetPriorityClass(WX.GetCurrentProcess, original)
        emit("priority_self") { |j| j.field "phase", phase; j.field "class", name; j.field "set_ok", rc != 0; j.field "set_error", err }
      end
    end
    exp_priority_caller
  end

  # The kit gets 1314 requesting a HIGH job class; the same request from this program succeeds. The two
  # callers differ in their own priority class (this program inherits BELOW_NORMAL from the runner), so
  # test the request from each caller class.
  def self.exp_priority_caller : Nil
    original = WX.GetPriorityClass(WX.GetCurrentProcess)
    PRIORITY_CLASSES.each do |caller_name, caller_value|
      next if caller_name == "realtime"
      WX.SetPriorityClass(WX.GetCurrentProcess, caller_value)
      actual_caller = WX.GetPriorityClass(WX.GetCurrentProcess)
      {"high", "realtime", "above_normal"}.each do |target|
        job = new_job
        begin
          info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
          info.basicLimitInformation.limitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE # the kit's request
          info.basicLimitInformation.priorityClass = PRIORITY_CLASSES[target]
          ok, err = set_job_info(job, CLASS_EXTENDED_LIMIT, pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION))
          emit("priority_caller") do |j|
            j.field "caller_class", caller_name
            j.field "caller_actual_hex", "0x#{actual_caller.to_s(16)}"
            j.field "target_class", target
            j.field "set_ok", ok
            j.field "set_error", err
          end
        ensure
          LibC.CloseHandle(job)
        end
      end
    end
    WX.SetPriorityClass(WX.GetCurrentProcess, original)
  end

  # --- cpu time --------------------------------------------------------------

  # One trial: a child that spins ~3.5 s of wall time inside a job (or with a per-process
  # limit). Samples job accounting every few ms to see when the limit is crossed and when
  # Windows actually terminates the child.
  def self.cpu_trial(kind : String, limit_ms : Int32, trial : Int32) : Nil
    job = new_job
    port = associate_port(job, 0x77_u64)
    process = nil.as(LibC::HANDLE?)
    begin
      info = LibC::JOBOBJECT_BASIC_LIMIT_INFORMATION.new
      if kind == "job"
        info.limitFlags = JOB_OBJECT_LIMIT_JOB_TIME
        info.perJobUserTimeLimit = limit_ms.to_i64 * 10_000_i64
      else
        info.limitFlags = JOB_OBJECT_LIMIT_PROCESS_TIME
        info.perProcessUserTimeLimit = limit_ms.to_i64 * 10_000_i64
      end
      ok, err = set_job_info(job, CLASS_BASIC_LIMIT, pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_BASIC_LIMIT_INFORMATION))
      raise "set limit failed: #{err}" unless ok

      proc, _ = start_in_job(job, [exe, "child-spin", "3500"])
      process = proc
      t0 = Time.instant
      msgs = [] of {UInt32, Float64}
      first_over_ms = -1.0
      last_user_ms = 0.0
      samples = 0
      exit_ms = -1.0
      while (Time.instant - t0) < 5.seconds
        now_ms = (Time.instant - t0).total_milliseconds
        if acct = query_basic_accounting(job)
          samples += 1
          last_user_ms = acct.total_user_time.to_f64 / 10_000.0
          first_over_ms = now_ms if first_over_ms < 0 && last_user_ms >= limit_ms
        end
        drain(port, t0, msgs)
        if process_done?(proc)
          exit_ms = (Time.instant - t0).total_milliseconds
          break
        end
        sleep 2.milliseconds
      end
      drain(port, t0, msgs)
      code = process_done?(proc) ? exit_code(proc) : 0xffff_ffff_u32
      user_ms = process_user_ms(proc)
      emit("cpu_trial") do |j|
        j.field "limit_kind", kind
        j.field "limit_ms", limit_ms
        j.field "trial", trial
        j.field "exit_code_hex", "0x#{code.to_s(16)}"
        j.field "killed", code != 0_u32 && code != 0xffff_ffff_u32
        j.field "timed_out_waiting", !process_done?(proc)
        j.field "exit_at_ms", exit_ms.round(2)
        j.field "first_sample_over_limit_ms", first_over_ms.round(2)
        j.field "kill_latency_after_over_ms", (exit_ms >= 0 && first_over_ms >= 0 ? (exit_ms - first_over_ms).round(2) : -1.0)
        j.field "user_ms_at_last_sample", last_user_ms.round(2)
        j.field "process_user_ms_final", user_ms.round(2)
        j.field "accounting_samples", samples
        j.field "messages" do
          j.array { msgs.each { |m, t| j.object { j.field "msg", m; j.field "at_ms", t.round(2) } } }
        end
      end
    rescue ex
      emit("cpu_trial_error") { |j| j.field "limit_kind", kind; j.field "limit_ms", limit_ms; j.field "trial", trial; j.field "error", ex.message || ex.class.name }
    ensure
      cleanup(process, job, port)
    end
  end

  def self.exp_cpu_time : Nil
    trials = (ENV["EXPLORE_CPU_TRIALS"]? || "10").to_i
    ["job", "process"].each do |kind|
      [50, 150, 300].each do |limit_ms|
        trials.times { |trial| cpu_trial(kind, limit_ms, trial) }
      end
    end
  end

  # --- cpu-time period ----------------------------------------------------------

  def self.start_spinner(limit_ms : Int32, max_ms : Int32) : {LibC::HANDLE, LibC::HANDLE, LibC::HANDLE}
    job = new_job
    port = associate_port(job, 0x99_u64)
    info = LibC::JOBOBJECT_BASIC_LIMIT_INFORMATION.new
    info.limitFlags = JOB_OBJECT_LIMIT_JOB_TIME
    info.perJobUserTimeLimit = limit_ms.to_i64 * 10_000_i64
    ok, err = set_job_info(job, CLASS_BASIC_LIMIT, pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_BASIC_LIMIT_INFORMATION))
    raise "set limit failed: #{err}" unless ok
    proc, _ = start_in_job(job, [exe, "child-spin", max_ms.to_s])
    {job, port, proc}
  end

  # Hypothesis from the cpu-time runs: Windows checks job CPU-time (and notification) limits in a
  # periodic system-wide pass, not when the limit is crossed. Measure that period directly:
  #   sequential - each spinner is killed at the next pass, so successive kills are one period apart
  #   concurrent - two jobs started 2.5 s apart; a global pass kills both at the same instant,
  #                a per-job timer would not
  def self.exp_cpu_period : Nil
    program_start = Time.instant
    ms = ->(t : Time::Instant) { (t - program_start).total_milliseconds.round(1) }

    6.times do |i|
      started = Time.instant
      job, port, proc = start_spinner(100, 20_000)
      begin
        while !process_done?(proc) && (Time.instant - started) < 25.seconds
          sleep 5.milliseconds
        end
        ended = Time.instant
        code = process_done?(proc) ? exit_code(proc) : 0xffff_ffff_u32
        emit("cpu_period_sequential") do |j|
          j.field "trial", i
          j.field "started_at_ms", ms.call(started)
          j.field "ended_at_ms", ms.call(ended)
          j.field "lived_ms", (ended - started).total_milliseconds.round(1)
          j.field "exit_code_hex", "0x#{code.to_s(16)}"
        end
      ensure
        cleanup(proc, job, port)
      end
    end

    a_job, a_port, a_proc = start_spinner(100, 20_000)
    a_start = Time.instant
    sleep 2500.milliseconds
    b_job, b_port, b_proc = start_spinner(100, 20_000)
    b_start = Time.instant
    a_end = nil.as(Time::Instant?)
    b_end = nil.as(Time::Instant?)
    deadline = Time.instant + 25.seconds
    while Time.instant < deadline && (a_end.nil? || b_end.nil?)
      a_end = Time.instant if a_end.nil? && process_done?(a_proc)
      b_end = Time.instant if b_end.nil? && process_done?(b_proc)
      sleep 5.milliseconds
    end
    emit("cpu_period_concurrent") do |j|
      j.field "a_started_at_ms", ms.call(a_start)
      j.field "b_started_at_ms", ms.call(b_start)
      j.field "a_ended_at_ms", a_end ? ms.call(a_end.not_nil!) : -1.0
      j.field "b_ended_at_ms", b_end ? ms.call(b_end.not_nil!) : -1.0
      j.field "a_exit_code_hex", "0x#{(process_done?(a_proc) ? exit_code(a_proc) : 0xffff_ffff_u32).to_s(16)}"
      j.field "b_exit_code_hex", "0x#{(process_done?(b_proc) ? exit_code(b_proc) : 0xffff_ffff_u32).to_s(16)}"
    end
    cleanup(a_proc, a_job, a_port)
    cleanup(b_proc, b_job, b_port)
  end

  # --- notification limits ---------------------------------------------------

  def self.notify_case(name : String, flags : UInt32, read_limit : UInt64, write_limit : UInt64, job_time_100ns : Int64,
                       child_args : Array(String), watch_ms : Int32) : Nil
    job = new_job
    port = associate_port(job, 0x55aa_u64)
    process = nil.as(LibC::HANDLE?)
    begin
      limit = WX::JobNotificationLimit.new
      limit.io_read_bytes_limit = read_limit
      limit.io_write_bytes_limit = write_limit
      limit.per_job_user_time_limit = job_time_100ns
      limit.limit_flags = flags
      ok, err = set_job_info(job, CLASS_NOTIFICATION_LIMIT, pointerof(limit).as(Void*), sizeof(WX::JobNotificationLimit))
      raise "set notification limit failed: #{err}" unless ok

      proc, _ = start_in_job(job, child_args)
      process = proc
      t0 = Time.instant
      msgs = [] of {UInt32, Float64}
      first_violation_ms = -1.0
      first_violation_flags = 0_u32
      exit_ms = -1.0
      timeline = [] of {Float64, UInt64, UInt64, Float64}
      next_sample = 0.0
      query_failed = 0
      while (Time.instant - t0).total_milliseconds < watch_ms
        now_ms = (Time.instant - t0).total_milliseconds
        drain(port, t0, msgs)
        qok, _qerr, v = query_violation(job)
        query_failed += 1 unless qok
        if qok && v.violation_limit_flags != 0 && first_violation_ms < 0
          first_violation_ms = now_ms
          first_violation_flags = v.violation_limit_flags
        end
        if now_ms >= next_sample
          if io = query_io_accounting(job)
            timeline << {now_ms.round(1), io.io.writeTransferCount, io.io.readTransferCount, (io.basic.total_user_time.to_f64 / 10_000.0).round(1)}
          end
          next_sample += 500.0
        end
        exit_ms = now_ms if exit_ms < 0 && process_done?(proc)
        sleep 25.milliseconds
      end
      drain(port, t0, msgs)
      qok, _qerr, final = query_violation(job)
      emit("notify_case") do |j|
        j.field "case", name
        j.field "limit_flags_hex", "0x#{flags.to_s(16)}"
        j.field "write_limit", write_limit
        j.field "read_limit", read_limit
        j.field "job_time_limit_ms", job_time_100ns / 10_000
        j.field "watch_ms", watch_ms
        j.field "child_exit_at_ms", exit_ms.round(1)
        j.field "got_notification_message_11", msgs.any? { |m, _| m == 11_u32 }
        j.field "first_violation_flag_ms", first_violation_ms.round(1)
        j.field "first_violation_flags_hex", "0x#{first_violation_flags.to_s(16)}"
        j.field "final_query_ok", qok
        j.field "final_violation_flags_hex", "0x#{final.violation_limit_flags.to_s(16)}"
        j.field "final_io_write_bytes", final.io_write_bytes
        j.field "final_io_read_bytes", final.io_read_bytes
        j.field "query_failures", query_failed
        j.field "messages" do
          j.array { msgs.each { |m, t| j.object { j.field "msg", m; j.field "at_ms", t.round(1) } } }
        end
        j.field "io_timeline" do
          j.array do
            timeline.each do |t, w, r, u|
              j.object { j.field "at_ms", t; j.field "write_bytes", w; j.field "read_bytes", r; j.field "user_ms", u }
            end
          end
        end
      end
    rescue ex
      emit("notify_case_error") { |j| j.field "case", name; j.field "error", ex.message || ex.class.name }
    ensure
      cleanup(process, job, port)
    end
  end

  def self.exp_notify : Nil
    dir = tmpdir
    Dir.mkdir_p(dir)
    write_path = File.join(dir, "explore-notify-write.bin")
    read_path = File.join(dir, "explore-notify-read.bin")
    File.open(read_path, "w") { |io| 128.times { io.write(Bytes.new(64 * 1024, 0x61_u8)) } } # 8 MiB, written by the parent (not in any job)

    # 4 MiB written then the child exits at once: exactly what the kit's io-work child does.
    notify_case("write_4MiB_child_exits", JOB_OBJECT_LIMIT_JOB_WRITE_BYTES, 0_u64, 65_536_u64, 0_i64,
      [exe, "child-write", write_path, "4", "0", "0"], 8000)
    # same, but the child stays alive afterwards
    notify_case("write_4MiB_child_stays_alive", JOB_OBJECT_LIMIT_JOB_WRITE_BYTES, 0_u64, 65_536_u64, 0_i64,
      [exe, "child-write", write_path, "4", "7000", "0"], 8000)
    # 64 MiB, child stays alive
    notify_case("write_64MiB_child_stays_alive", JOB_OBJECT_LIMIT_JOB_WRITE_BYTES, 0_u64, 65_536_u64, 0_i64,
      [exe, "child-write", write_path, "64", "7000", "0"], 8000)
    # FlushFileBuffers after writing
    notify_case("write_4MiB_fsync_child_stays_alive", JOB_OBJECT_LIMIT_JOB_WRITE_BYTES, 0_u64, 65_536_u64, 0_i64,
      [exe, "child-write", write_path, "4", "7000", "1"], 8000)
    # read-bytes notification
    notify_case("read_8MiB_child_stays_alive", JOB_OBJECT_LIMIT_JOB_READ_BYTES, 65_536_u64, 0_u64, 0_i64,
      [exe, "child-read", read_path, "7000"], 8000)
    # job-time notification (informational: must NOT kill the child)
    notify_case("job_time_100ms_spin", JOB_OBJECT_LIMIT_JOB_TIME, 0_u64, 0_u64, 1_000_000_i64,
      [exe, "child-spin", "3000"], 6000)

    File.delete?(write_path)
    File.delete?(read_path)
  end

  # --- unelevated launcher -----------------------------------------------------

  # Runs `args` with a filtered copy of this process's token: administrator groups
  # become deny-only, privileges are stripped, integrity is lowered to Medium. This is
  # what a UAC-unelevated process of an administrator account looks like.
  def self.launch_unelevated(args : Array(String)) : Int32
    base = open_token(0x008b_u32) # ASSIGN_PRIMARY 0x1 | DUPLICATE 0x2 | QUERY 0x8 | ADJUST_DEFAULT 0x80
    restricted = LibC::HANDLE.null
    # DISABLE_MAX_PRIVILEGE (0x1) | LUA_TOKEN (0x4)
    if WX.CreateRestrictedToken(base, 0x5_u32, 0_u32, Pointer(Void).null, 0_u32, Pointer(Void).null, 0_u32, Pointer(Void).null, pointerof(restricted)) == 0
      STDERR.puts "CreateRestrictedToken failed: #{LibC.GetLastError}"
      return 90
    end

    medium_sid = Pointer(LibC::SID).null
    if LibC.ConvertStringSidToSidW(wide("S-1-16-8192").to_unsafe, pointerof(medium_sid)) == 0
      STDERR.puts "ConvertStringSidToSid failed: #{LibC.GetLastError}"
      return 91
    end
    label = WX::SidAndAttributes.new
    label.sid = medium_sid.as(Void*)
    label.attributes = 0x20_u32 # SE_GROUP_INTEGRITY
    if WX.SetTokenInformation(restricted, 25_u32, pointerof(label).as(Void*), (sizeof(WX::SidAndAttributes) + WX.GetLengthSid(medium_sid.as(Void*))).to_u32) == 0
      STDERR.puts "SetTokenInformation(integrity) failed: #{LibC.GetLastError} (continuing at the inherited integrity level)"
    end

    # CreateProcessAsUser may need SeIncreaseQuotaPrivilege; the caller is elevated, so enable it if held.
    enable_privilege("SeIncreaseQuotaPrivilege")
    enable_privilege("SeAssignPrimaryTokenPrivilege")

    command_line = Process.quote_windows(args).to_utf16
    startup = LibC::STARTUPINFOW.new
    startup.cb = sizeof(LibC::STARTUPINFOW).to_u32
    # Without STARTF_USESTDHANDLES a console program started from a console-less CI step gets a
    # fresh hidden console and its output is lost. Hand it our own (inheritable) std handles.
    inherited = [] of LibC::HANDLE
    {0xfffffff6_u32, 0xfffffff5_u32, 0xfffffff4_u32}.each do |kind|
      h = LibC.GetStdHandle(kind)
      valid = !h.null? && h != INVALID_HANDLE_VALUE
      WX.SetHandleInformation(h, 1_u32, 1_u32) if valid # HANDLE_FLAG_INHERIT
      inherited << (valid ? h : LibC::HANDLE.null)
    end
    startup.dwFlags = 0x100_u32 # STARTF_USESTDHANDLES
    startup.hStdInput = inherited[0]
    startup.hStdOutput = inherited[1]
    startup.hStdError = inherited[2]
    info = LibC::PROCESS_INFORMATION.new
    rc = WX.CreateProcessAsUserW(restricted, Pointer(UInt16).null, command_line.to_unsafe,
      Pointer(LibC::SECURITY_ATTRIBUTES).null, Pointer(LibC::SECURITY_ATTRIBUTES).null,
      1, 0_u32, Pointer(Void).null, Pointer(UInt16).null, pointerof(startup), pointerof(info))
    if rc == 0
      STDERR.puts "CreateProcessAsUserW failed: #{LibC.GetLastError}"
      return 92
    end
    LibC.CloseHandle(info.hThread)
    LibC.WaitForSingleObject(info.hProcess, 0xffff_ffff_u32)
    code = exit_code(info.hProcess)
    LibC.CloseHandle(info.hProcess)
    code.to_i32!
  end

  # --- children --------------------------------------------------------------

  def self.child_spin(ms : Int32) : Nil
    deadline = Time.instant + ms.milliseconds
    value = 0x1234_5678_u64
    while Time.instant < deadline
      50_000.times { value = value &* 6364136223846793005_u64 &+ 1442695040888963407_u64 }
    end
    exit(value == 0 ? 1 : 0)
  end

  def self.child_write(path : String, mb : Int32, sleep_ms : Int32, fsync : Bool) : Nil
    chunk = Bytes.new(64 * 1024, 0x6b_u8)
    File.open(path, "w") do |io|
      (mb * 16).times { io.write(chunk) }
      io.flush
      io.fsync if fsync
    end
    sleep sleep_ms.milliseconds
    exit 0
  end

  def self.child_read(path : String, sleep_ms : Int32) : Nil
    buffer = Bytes.new(64 * 1024)
    File.open(path) { |io| while io.read(buffer) > 0; end }
    sleep sleep_ms.milliseconds
    exit 0
  end

  def self.main : Nil
    case ARGV[0]?
    when "token"    then exp_token
    when "priority" then exp_priority
    when "cpu-time" then exp_cpu_time
    when "cpu-period" then exp_cpu_period
    when "notify"   then exp_notify
    when "all"
      exp_token
      exp_priority
      exp_notify
      exp_cpu_period
      exp_cpu_time
    when "launch-unelevated"
      split = ARGV.index("--") || raise "usage: launch-unelevated -- <command...>"
      exit launch_unelevated(ARGV[(split + 1)..])
    when "child-spin"  then child_spin(ARGV[1].to_i)
    when "child-sleep" then (sleep ARGV[1].to_i.milliseconds; exit 0)
    when "child-write" then child_write(ARGV[1], ARGV[2].to_i, ARGV[3].to_i, ARGV[4] == "1")
    when "child-read"  then child_read(ARGV[1], ARGV[2].to_i)
    else
      STDERR.puts "usage: job_explore (token|priority|cpu-time|notify|all|launch-unelevated -- cmd...)"
      exit 64
    end
  end
end

Explore.main
