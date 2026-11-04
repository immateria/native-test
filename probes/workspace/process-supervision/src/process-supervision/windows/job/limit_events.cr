{% if flag?(:win32) %}
  module ProcessSupervision::Windows
    class Job
      module Limit
        record Event, kind : Event::Kind, pid : Int64? do
          enum Kind : UInt32
            EndOfJobTime        =  1
            EndOfProcessTime    =  2
            ActiveProcessLimit  =  3
            AbnormalExitProcess =  8
            ProcessMemoryLimit  =  9
            JobMemoryLimit      = 10
          end
        end
      end

      private class EventReader
        JOB_KEY    = LibC::ULONG_PTR.new(1)
        STOP_KEY   = LibC::ULONG_PTR.new(2)
        MAX_EVENTS = 1024

        @thread : Thread

        def initialize(job : LibC::HANDLE)
          @lock = Thread::Mutex.new
          @close_lock = Thread::Mutex.new
          @stopped = false
          @reader_stopped = Atomic(Bool).new(false)
          @events = [] of Limit::Event
          @port = LibC.CreateIoCompletionPort(Native::INVALID_HANDLE_VALUE, LibC::HANDLE.null, Pointer(LibC::ULong).null, 1)
          raise Native.error("CreateIoCompletionPort(Job events)") if @port.null?

          associate = LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT.new(
            completionKey: Pointer(Void).new(JOB_KEY), completionPort: @port
          )
          if LibC.SetInformationJobObject(
               job, LibC::JOBOBJECTINFOCLASS::AssociateCompletionPortInformation,
               pointerof(associate).as(Void*), sizeof(LibC::JOBOBJECT_ASSOCIATE_COMPLETION_PORT).to_u32
             ) == 0
            error = Native.error("SetInformationJobObject(JobObjectAssociateCompletionPortInformation)")
            # Constructor rollback owns a stronger primary diagnosis; do not let
            # completion-port cleanup replace it.
            Native.close_native_handle(@port)
            raise error
          end

          port = @port
          @thread = Thread.new do
            begin
              read_events(port)
            ensure
              @reader_stopped.set(true)
            end
          end
        end

        def events : Array(Limit::Event)
          @lock.synchronize { @events.dup }
        end

        def close : Nil
          @close_lock.synchronize do
            return if @port.null?

            unless @stopped
              if LibC.PostQueuedCompletionStatus(@port, 0, STOP_KEY, Pointer(LibC::OVERLAPPED).null) == 0
                raise Native.error("PostQueuedCompletionStatus(Job event stop)")
              end
              # Crystal 1.22.x Thread#join detaches the Thread object before the
              # target thread runs its self-cleanup path on Windows. That path owns
              # the per-Thread semaphore; joining here leaks one kernel HANDLE per
              # EventReader. Wait only for this reader loop to finish and let the
              # raw Thread perform its own system cleanup. Thread.sleep works even
              # when Job#close is entered from a raw thread without an execution
              # context.
              until @reader_stopped.get
                Thread.sleep(1.millisecond)
              end
              @stopped = true
            end

            # Keep the port attached until checked close succeeds. If this
            # fails after the reader has stopped, a later close retries only
            # CloseHandle rather than restarting or reposting the reader.
            Native.close_handle(@port, "CloseHandle(Job event completion port)")
            @port = LibC::HANDLE.null
          end
        end

        def closed? : Bool
          @close_lock.synchronize { @port.null? }
        end

        private def read_events(port : LibC::HANDLE) : Nil
          entry = LibC::OVERLAPPED_ENTRY.new
          loop do
            removed = LibC::ULong.new(0)
            break if LibC.GetQueuedCompletionStatusEx(port, pointerof(entry), 1, pointerof(removed), Native::INFINITE, 0) == 0
            next if removed == 0
            break if entry.lpCompletionKey == STOP_KEY
            next unless entry.lpCompletionKey == JOB_KEY
            next unless kind = Limit::Event::Kind.from_value?(entry.dwNumberOfBytesTransferred)

            address = entry.lpOverlapped.address
            pid = address == 0 ? nil : address.to_i64
            @lock.synchronize { @events << Limit::Event.new(kind, pid) if @events.size < MAX_EVENTS }
          end
        end
      end
    end
  end
{% end %}
