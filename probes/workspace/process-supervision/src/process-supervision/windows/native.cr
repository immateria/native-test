{% if flag?(:win32) %}
  require "c/fileapi"
  require "c/handleapi"
  require "c/processenv"
  require "c/processthreadsapi"
  require "c/wtypesbase"

  module ProcessSupervision::Windows
    @[Link("kernel32")]
    private lib NativeLib
      struct BasicAndIOAccounting
        total_user_time : Int64
        total_kernel_time : Int64
        this_period_total_user_time : Int64
        this_period_total_kernel_time : Int64
        total_page_fault_count : UInt32
        total_processes : UInt32
        active_processes : UInt32
        total_terminated_processes : UInt32
        io_info : LibC::IO_COUNTERS
      end

      fun QueryInformationJobObject(job : LibC::HANDLE, info_class : UInt32, info : Void*, length : UInt32, return_length : UInt32*) : LibC::BOOL
      fun TerminateJobObject(job : LibC::HANDLE, exit_code : UInt32) : LibC::BOOL

      fun InitializeProcThreadAttributeList(attribute_list : Void*, attribute_count : UInt32,
                                            flags : UInt32, size : LibC::SizeT*) : LibC::BOOL
      fun UpdateProcThreadAttribute(attribute_list : Void*, flags : UInt32, attribute : LibC::SizeT,
                                    value : Void*, size : LibC::SizeT, previous_value : Void*,
                                    return_size : LibC::SizeT*) : LibC::BOOL
      fun DeleteProcThreadAttributeList(attribute_list : Void*) : Void

      fun GetCurrentProcess : LibC::HANDLE
      fun GetStdHandle(kind : UInt32) : LibC::HANDLE
      fun DuplicateHandle(source_process : LibC::HANDLE, source_handle : LibC::HANDLE,
                          target_process : LibC::HANDLE, target_handle : LibC::HANDLE*,
                          desired_access : UInt32, inherit_handle : LibC::BOOL,
                          options : UInt32) : LibC::BOOL
      fun GetEnvironmentStringsW : UInt16*
      fun FreeEnvironmentStringsW(block : UInt16*) : LibC::BOOL
    end

    private struct StartupInfoExW
      property startup_info : LibC::STARTUPINFOW
      property attribute_list : Void*

      def initialize
        @startup_info = LibC::STARTUPINFOW.new
        @attribute_list = Pointer(Void).null
      end
    end

    private module Native
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000_u32
      INVALID_HANDLE_VALUE               = LibC::HANDLE.new(UInt64::MAX)
      INFINITE                           = 0xffff_ffff_u32

      EXTENDED_STARTUPINFO_PRESENT      = 0x00080000_u32
      CREATE_UNICODE_ENVIRONMENT        = 0x00000400_u32
      CREATE_SUSPENDED                  = 0x00000004_u32
      STARTF_USESTDHANDLES              = 0x00000100_u32
      PROC_THREAD_ATTRIBUTE_HANDLE_LIST = LibC::SizeT.new(0x00020002_u64)
      PROC_THREAD_ATTRIBUTE_JOB_LIST    = LibC::SizeT.new(0x0002000D_u64)

      DUPLICATE_SAME_ACCESS = 0x00000002_u32
      STD_INPUT_HANDLE      = 0xfffffff6_u32
      STD_OUTPUT_HANDLE     = 0xfffffff5_u32
      STD_ERROR_HANDLE      = 0xfffffff4_u32
      GENERIC_READ          = 0x80000000_u32
      GENERIC_WRITE         = 0x40000000_u32
      FILE_SHARE_READ       = 0x00000001_u32
      FILE_SHARE_WRITE      = 0x00000002_u32
      OPEN_EXISTING         =          3_u32
      FILE_ATTRIBUTE_NORMAL = 0x00000080_u32

      def self.error(operation : String, code : UInt32 = LibC.GetLastError) : ProcessSupervision::Error::Native
        native = WinError.new(code)
        ProcessSupervision::Error::Native.new(operation, native.message, code.to_i64)
      end

      def self.close_handle(handle : LibC::HANDLE, operation : String = "CloseHandle") : Nil
        return if handle.null?
        raise error(operation) if LibC.CloseHandle(handle) == 0
      end

      def self.close_native_handle(handle : LibC::HANDLE) : Nil
        LibC.CloseHandle(handle) unless handle.null?
      end

      def self.process_creation_time(handle : LibC::HANDLE, operation : String = "GetProcessTimes") : UInt64
        creation_time = uninitialized LibC::FILETIME
        exit_time = uninitialized LibC::FILETIME
        kernel_time = uninitialized LibC::FILETIME
        user_time = uninitialized LibC::FILETIME
        if LibC.GetProcessTimes(handle, pointerof(creation_time), pointerof(exit_time), pointerof(kernel_time), pointerof(user_time)) == 0
          raise error(operation)
        end
        (creation_time.dwHighDateTime.to_u64 << 32) | creation_time.dwLowDateTime.to_u64
      end

      def self.duplicate_inheritable(handle : LibC::HANDLE, operation : String) : LibC::HANDLE
        current = NativeLib.GetCurrentProcess
        duplicate = LibC::HANDLE.null
        if NativeLib.DuplicateHandle(current, handle, current, pointerof(duplicate), 0_u32, 1, DUPLICATE_SAME_ACCESS) == 0
          raise error(operation)
        end
        duplicate
      end

      def self.standard_handle(kind : UInt32, *, input : Bool) : LibC::HANDLE
        source = NativeLib.GetStdHandle(kind)
        unless source.null? || source == INVALID_HANDLE_VALUE
          return duplicate_inheritable(source, "DuplicateHandle(standard stream)")
        end

        security = LibC::SECURITY_ATTRIBUTES.new(
          nLength: sizeof(LibC::SECURITY_ATTRIBUTES).to_u32,
          lpSecurityDescriptor: Pointer(Void).null,
          bInheritHandle: 1
        )
        nul = "NUL".to_utf16
        access = input ? GENERIC_READ : GENERIC_WRITE
        handle = LibC.CreateFileW(
          nul.to_unsafe,
          access,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          pointerof(security),
          OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL,
          LibC::HANDLE.null
        )
        if handle == INVALID_HANDLE_VALUE
          raise error("CreateFileW(NUL standard stream)")
        end
        handle
      end

      # Windows has hidden per-drive environment entries such as `=C:` which
      # ENV intentionally omits. Preserve them when rebuilding an inherited
      # environment block so a supervised spawn matches CreateProcessW's normal
      # inheritance semantics.
      def self.reserved_environment_entries : Array(String)
        block = NativeLib.GetEnvironmentStringsW
        return [] of String if block.null?

        entries = [] of String
        begin
          cursor = block
          loop do
            length = 0
            while cursor[length] != 0_u16
              length += 1
            end
            break if length == 0
            entries << String.from_utf16(Slice.new(cursor, length)) if cursor[0] == '='.ord
            cursor += length + 1
          end
        ensure
          NativeLib.FreeEnvironmentStringsW(block)
        end
        entries
      end
    end
  end
{% end %}
