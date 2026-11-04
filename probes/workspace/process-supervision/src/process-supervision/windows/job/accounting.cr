{% if flag?(:win32) %}
  module ProcessSupervision::Windows
    class Job
      struct Accounting
        private BASIC_AND_IO_ACCOUNTING_CLASS = 8_u32
        private EXTENDED_LIMIT_CLASS          = 9_u32

        getter user_time : Time::Span
        getter kernel_time : Time::Span
        getter page_faults : UInt32
        getter total_processes : UInt32
        getter active_processes : UInt32
        getter terminated_processes : UInt32
        getter read_operations : UInt64
        getter write_operations : UInt64
        getter other_operations : UInt64
        getter read_bytes : UInt64
        getter write_bytes : UInt64
        getter other_bytes : UInt64
        getter peak_job_memory : UInt64
        getter peak_process_memory : UInt64

        def initialize(accounting : NativeLib::BasicAndIOAccounting,
                       limits : LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
          @user_time = Time::Span.new(nanoseconds: accounting.total_user_time * 100)
          @kernel_time = Time::Span.new(nanoseconds: accounting.total_kernel_time * 100)
          @page_faults = accounting.total_page_fault_count
          @total_processes = accounting.total_processes
          @active_processes = accounting.active_processes
          @terminated_processes = accounting.total_terminated_processes
          io = accounting.io_info
          @read_operations = io.readOperationCount
          @write_operations = io.writeOperationCount
          @other_operations = io.otherOperationCount
          @read_bytes = io.readTransferCount
          @write_bytes = io.writeTransferCount
          @other_bytes = io.otherTransferCount
          @peak_job_memory = limits.peakJobMemoryUsed.to_u64
          @peak_process_memory = limits.peakProcessMemoryUsed.to_u64
        end

        def self.query(job : LibC::HANDLE) : self
          accounting = NativeLib::BasicAndIOAccounting.new
          if NativeLib.QueryInformationJobObject(
               job, BASIC_AND_IO_ACCOUNTING_CLASS, pointerof(accounting).as(Void*),
               sizeof(NativeLib::BasicAndIOAccounting).to_u32, Pointer(UInt32).null
             ) == 0
            raise Native.error("QueryInformationJobObject(JobObjectBasicAndIoAccountingInformation)")
          end

          limits = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
          if NativeLib.QueryInformationJobObject(
               job, EXTENDED_LIMIT_CLASS, pointerof(limits).as(Void*),
               sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION).to_u32, Pointer(UInt32).null
             ) == 0
            raise Native.error("QueryInformationJobObject(JobObjectExtendedLimitInformation)")
          end
          new(accounting, limits)
        end
      end
    end
  end
{% end %}
