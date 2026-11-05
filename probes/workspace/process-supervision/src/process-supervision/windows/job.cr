{% if flag?(:win32) %}
  module ProcessSupervision::Windows
    class Job
      private JOB_OBJECT_LIMIT_PROCESS_TIME      = 0x0002_u32
      private JOB_OBJECT_LIMIT_JOB_TIME          = 0x0004_u32
      private JOB_OBJECT_LIMIT_ACTIVE_PROCESS    = 0x0008_u32
      private JOB_OBJECT_LIMIT_PRIORITY_CLASS    = 0x0020_u32
      private JOB_OBJECT_LIMIT_PROCESS_MEMORY    = 0x0100_u32
      private JOB_OBJECT_LIMIT_JOB_MEMORY        = 0x0200_u32
      private BASIC_UI_RESTRICTIONS_CLASS        =          4
      private CPU_RATE_CONTROL_INFORMATION_CLASS =         15
      private CPU_RATE_CONTROL_ENABLE_HARD_CAP   = 0x1_u32 | 0x4_u32

      @events : EventReader? = nil

      def initialize(limits : Job::Limits? = nil)
        limits.try &.validate!
        @mutex = Thread::Mutex.new
        @close_lock = Thread::Mutex.new
        @handle = LibC.CreateJobObjectW(Pointer(LibC::SECURITY_ATTRIBUTES).null, Pointer(UInt16).null)
        raise Native.error("CreateJobObjectW") if @handle.null?

        begin
          configure(limits)
          @events = EventReader.new(@handle) if limits
        rescue ex
          close rescue nil
          raise ex
        end
      end

      def mechanism : ProcessSupervision::Mechanism
        ProcessSupervision::Mechanism::JobObject
      end

      def kill_on_close? : Bool
        true
      end

      def soft_termination? : Bool
        false
      end

      # Assigns an already-running process. This operation cannot retroactively
      # contain descendants created before assignment; use a future atomic spawn
      # API when that guarantee is required.
      def adopt(process : ProcessHandle) : Nil
        windows = process.as?(ProcessHandle::Windows)
        raise ProcessSupervision::Error::Unsupported.new("a Windows Job can adopt only a Windows process HANDLE") unless windows

        access = ProcessHandle::Windows::Access::Terminate | ProcessHandle::Windows::Access::SetQuota
        windows.with_native_handle(access) do |native|
          @mutex.synchronize do
            checked_handle
            if LibC.AssignProcessToJobObject(@handle, native) == 0
              raise Native.error("AssignProcessToJobObject")
            end
          end
        end
      end

      def empty? : Bool
        accounting.active_processes == 0
      end

      def wait_empty(timeout : Time::Span? = nil) : Bool
        run_on_execution_context("process-supervision-windows-job-wait-empty") do
          wait_empty_on_execution_context(timeout)
        end
      end

      private def wait_empty_on_execution_context(timeout : Time::Span?) : Bool
        validate_timeout(timeout)
        deadline = timeout.try { |span| Time.instant + span }
        loop do
          return true if empty?
          if deadline
            remaining = deadline - Time.instant
            return false if remaining <= Time::Span.zero
            sleep({remaining, 10.milliseconds}.min)
          else
            sleep 10.milliseconds
          end
        end
      end

      def terminate : Nil
        raise ProcessSupervision::Error::Unsupported.new(
          "Windows Job Objects have no general cooperative tree-termination operation"
        )
      end

      def kill : Nil
        @mutex.synchronize do
          handle = checked_handle
          if NativeLib.TerminateJobObject(handle, 137_u32) == 0
            raise Native.error("TerminateJobObject")
          end
        end
      end

      def close : Nil
        @close_lock.synchronize do
          events = nil.as(EventReader?)
          @mutex.synchronize do
            return if @handle.null? && @events.nil?

            unless @handle.null?
              # The Job handle is owner-controlled and retryable: retain it
              # until checked CloseHandle succeeds, then publish logical close.
              Native.close_handle(@handle, "CloseHandle(Job)")
              @handle = LibC::HANDLE.null
            end
            events = @events
          end

          if reader = events
            # Session close hardening established that logical close is not
            # proof all nested cleanup finished. Keep the EventReader attached
            # until its own retryable cleanup succeeds.
            reader.close
            @mutex.synchronize do
              @events = nil if @events.same?(reader)
            end
          end
        end
      end

      def closed? : Bool
        @mutex.synchronize { @handle.null? }
      end

      def accounting : Job::Accounting
        @mutex.synchronize do
          handle = checked_handle
          Job::Accounting.query(handle)
        end
      end

      def limit_events : Array(Job::Limit::Event)
        reader = @mutex.synchronize do
          checked_handle
          @events
        end
        reader.try(&.events) || [] of Job::Limit::Event
      end

      private def configure(limits : Job::Limits?) : Nil
        info = LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION.new
        flags = Native::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if limits
          if bytes = limits.job_memory
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY
            info.jobMemoryLimit = LibC::SizeT.new(bytes)
          end
          if bytes = limits.process_memory
            flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.processMemoryLimit = LibC::SizeT.new(bytes)
          end
          if count = limits.active_processes
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.basicLimitInformation.activeProcessLimit = count
          end
          if span = limits.job_user_time
            flags |= JOB_OBJECT_LIMIT_JOB_TIME
            info.basicLimitInformation.perJobUserTimeLimit = span.total_nanoseconds.to_i64 // 100
          end
          if span = limits.process_user_time
            flags |= JOB_OBJECT_LIMIT_PROCESS_TIME
            info.basicLimitInformation.perProcessUserTimeLimit = span.total_nanoseconds.to_i64 // 100
          end
          if priority = limits.priority_class
            flags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS
            info.basicLimitInformation.priorityClass = priority.value
          end
          flags |= 0x0400_u32 if limits.die_on_unhandled_exception # JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        end
        info.basicLimitInformation.limitFlags = flags
        set_information(
          "SetInformationJobObject(JobObjectExtendedLimitInformation)",
          LibC::JOBOBJECTINFOCLASS::ExtendedLimitInformation,
          pointerof(info).as(Void*), sizeof(LibC::JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
        )

        return unless limits
        if percent = limits.cpu_rate_percent
          rate = StaticArray[CPU_RATE_CONTROL_ENABLE_HARD_CAP, (percent * 100).round.to_u32]
          set_information(
            "SetInformationJobObject(JobObjectCpuRateControlInformation)",
            LibC::JOBOBJECTINFOCLASS.new(CPU_RATE_CONTROL_INFORMATION_CLASS),
            rate.to_unsafe.as(Void*), sizeof(UInt32) * 2
          )
        end
        if restrictions = limits.ui_restrictions
          ui = restrictions.value
          set_information(
            "SetInformationJobObject(JobObjectBasicUIRestrictions)",
            LibC::JOBOBJECTINFOCLASS.new(BASIC_UI_RESTRICTIONS_CLASS),
            pointerof(ui).as(Void*), sizeof(UInt32)
          )
        end
      end

      private def set_information(operation : String, info_class : LibC::JOBOBJECTINFOCLASS, info : Void*, size : Int) : Nil
        if LibC.SetInformationJobObject(@handle, info_class, info, size.to_u32) == 0
          raise Native.error(operation)
        end
      end

      private def checked_handle : LibC::HANDLE
        raise ProcessSupervision::Error::Closed.new("Job is closed") if @handle.null?
        @handle
      end
    end
  end
{% end %}
