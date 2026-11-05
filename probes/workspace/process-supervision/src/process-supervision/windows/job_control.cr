{% if flag?(:win32) %}
  # Not `private`: Crystal 1.21 ignores @[Link] on a private lib, and user32 (EnumWindows, PostMessageW) is not
  # linked by the standard library. kernel32 is.
  @[Link("user32")]
  lib LibProcessSupervisionJobControl
    fun QueryInformationJobObject(job : LibC::HANDLE, info_class : UInt32, info : Void*, length : UInt32, return_length : UInt32*) : LibC::BOOL
    fun GenerateConsoleCtrlEvent(event : UInt32, group : UInt32) : LibC::BOOL
    alias EnumWindowsProc = (Void*, Int64) -> LibC::BOOL
    fun EnumWindows(callback : EnumWindowsProc, param : Int64) : LibC::BOOL
    fun GetWindowThreadProcessId(window : Void*, pid : UInt32*) : UInt32
    fun PostMessageW(window : Void*, message : UInt32, wparam : UInt64, lparam : Int64) : LibC::BOOL
  end

  module ProcessSupervision::Windows
    class Job
      private JOB_OBJECT_BASIC_PROCESS_ID_LIST =      3_u32
      private CTRL_BREAK_EVENT                 =      1_u32
      private WM_CLOSE                         = 0x0010_u32

      # The process ids in the Job right now (JobObjectBasicProcessIdList).
      def process_ids : Array(Int64)
        @mutex.synchronize do
          job = checked_handle
          capacity = 64
          loop do
            # JOBOBJECT_BASIC_PROCESS_ID_LIST: two DWORD counts, then ULONG_PTR ids
            buffer = Bytes.new(8 + capacity * sizeof(LibC::SizeT))
            if LibProcessSupervisionJobControl.QueryInformationJobObject(job, JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                 buffer.to_unsafe.as(Void*), buffer.size.to_u32, Pointer(UInt32).null) == 0
              code = LibC.GetLastError
              if code == 234 # ERROR_MORE_DATA
                capacity *= 4
                next
              end
              raise Native.error("QueryInformationJobObject(BasicProcessIdList)", code)
            end
            assigned = buffer.to_unsafe.as(UInt32*)[0]
            listed = buffer.to_unsafe.as(UInt32*)[1]
            if assigned > listed && capacity < 65_536
              capacity = assigned.to_i + 16
              next
            end
            ids = (buffer.to_unsafe + 8).as(LibC::SizeT*)
            return Array(Int64).new(listed.to_i) { |index| ids[index].to_i64 }
          end
        end
      end

      # Suspends every thread of every member (NtSuspendProcess). A process created after the listing is not suspended.
      def suspend : Nil
        each_member(&.suspend)
      end

      def resume : Nil
        each_member(&.resume)
      end

      # CTRL_BREAK_EVENT to every member that leads a console process group (spawned with
      # `SpawnOptions#console_group`; others ignore it) and WM_CLOSE to every top-level window a member owns.
      def request_stop : Nil
        ids = process_ids
        ids.each { |pid| LibProcessSupervisionJobControl.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid.to_u32) }
        members = ids.map(&.to_u32).to_set
        box = Box.box(members)
        LibProcessSupervisionJobControl.EnumWindows(->(window : Void*, param : Int64) {
          owner = 0_u32
          LibProcessSupervisionJobControl.GetWindowThreadProcessId(window, pointerof(owner))
          if Box(Set(UInt32)).unbox(Pointer(Void).new(param.to_u64)).includes?(owner)
            LibProcessSupervisionJobControl.PostMessageW(window, 0x0010_u32, 0_u64, 0_i64)
          end
          1
        }, box.address.to_i64)
      end

      private def each_member(& : ProcessHandle ->) : Nil
        process_ids.each do |pid|
          handle = begin
            ProcessHandle.open(pid)
          rescue ProcessHandle::Error
            next
          end
          begin
            yield handle
          rescue ProcessHandle::Error
          ensure
            handle.close rescue nil
          end
        end
      end
    end
  end
{% end %}
