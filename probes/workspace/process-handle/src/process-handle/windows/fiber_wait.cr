{% if flag?(:win32) %}
  class ProcessHandle::Windows
    # Bridges a Win32 registered process wait into Crystal's normal evented pipe
    # path. The foreign callback is allocation-free and scheduler-free. Callback
    # context is freed only after UnregisterWaitEx proves callback quiescence.
    private class FiberWait
      private struct CallbackContext
        private FAILURE_NONE        =           0_u64
        private FAILURE_WINERROR    =           1_u64
        private FAILURE_SHORT_WRITE =           2_u64
        private FAILURE_KIND_SHIFT  =              32
        private FAILURE_DETAIL_MASK = 0xffff_ffff_u64

        @write_handle = Atomic(UInt64).new(0_u64)
        @failure = Atomic(UInt64).new(FAILURE_NONE)
        @timed_out = Atomic(UInt32).new(0_u32)

        def initialize(write_handle : LibC::HANDLE)
          @write_handle.set(write_handle.address.to_u64)
        end

        # Foreign-thread callback path: keep allocation-free and scheduler-free.
        def signal(timed_out : LibC::BOOLEAN) : Nil
          @timed_out.set(timed_out == 0 ? 0_u32 : 1_u32)
          address = @write_handle.get
          return if address == 0_u64

          ok, written, native_error = Native.raw_write_one_byte(LibC::HANDLE.new(address))
          return if ok && written == 1_u32

          if ok
            record_failure(FAILURE_SHORT_WRITE, written)
          else
            record_failure(FAILURE_WINERROR, native_error)
          end

          # A failed physical wake must still settle the fiber-side OVERLAPPED
          # read. Closing the sole writer makes the read complete with EOF/error.
          close_write_handle
        end

        def close_write_handle : Nil
          address = @write_handle.swap(0_u64)
          return if address == 0_u64
          Native.close_native_handle(LibC::HANDLE.new(address))
        end

        def timed_out? : Bool
          @timed_out.get != 0_u32
        end

        def failure : ProcessHandle::Error::Native?
          encoded = @failure.get
          return nil if encoded == FAILURE_NONE

          kind = encoded >> FAILURE_KIND_SHIFT
          detail = (encoded & FAILURE_DETAIL_MASK).to_u32
          case kind
          when FAILURE_WINERROR
            ProcessHandle::Error::Native.new(
              "registered process wait wake", WinError.new(detail).message, detail.to_i64
            )
          when FAILURE_SHORT_WRITE
            ProcessHandle::Error::Native.new("registered process wait wake", "short pipe write #{detail}")
          else
            ProcessHandle::Error::Native.new("registered process wait wake", "unknown failure #{encoded}")
          end
        end

        private def record_failure(kind : UInt64, detail : UInt32) : Nil
          encoded = (kind << FAILURE_KIND_SHIFT) | detail.to_u64
          @failure.compare_and_set(FAILURE_NONE, encoded)
        end
      end

      private CALLBACK = ->(raw : Void*, timed_out : LibC::BOOLEAN) do
        raw.as(CallbackContext*).value.signal(timed_out) unless raw.null?
      end

      @read : IO::FileDescriptor?
      @context : CallbackContext*
      @wait_handle : LibC::HANDLE

      private def initialize(process_handle : LibC::HANDLE, milliseconds : UInt32)
        @read = nil
        @context = Pointer(CallbackContext).null
        @wait_handle = LibC::HANDLE.null

        read_pipe, write_pipe = IO.pipe(read_blocking: false, write_blocking: true)
        write_detached = false
        begin
          context = LibC.malloc(sizeof(CallbackContext)).as(CallbackContext*)
          raise RuntimeError.new("failed to allocate process-wait callback context") if context.null?

          context.value = CallbackContext.new(LibC::HANDLE.new(write_pipe.fd.to_u64))
          write_pipe.close_on_finalize = false
          write_detached = true

          @read = read_pipe
          @context = context
          @wait_handle = Native.register_wait(process_handle, CALLBACK, context.as(Void*), milliseconds)
        rescue ex
          if write_detached && !@context.null?
            @context.value.close_write_handle
          else
            write_pipe.close rescue nil
          end
          read_pipe.close rescue nil
          LibC.free(@context.as(Void*)) unless @context.null?
          @context = Pointer(CallbackContext).null
          raise ex
        end
      end

      def self.wait(process_handle : LibC::HANDLE, timeout : Time::Span?) : Bool
        return new(process_handle, Native::INFINITE).wait unless timeout

        max_milliseconds = (Native::INFINITE - 1_u32).to_i64
        max_timeout = max_milliseconds.milliseconds
        remaining = timeout

        while remaining > max_timeout
          return true if new(process_handle, Native::INFINITE - 1_u32).wait
          remaining -= max_timeout
        end

        new(process_handle, Native.registered_wait_milliseconds(remaining)).wait
      end

      def wait : Bool
        error = nil.as(Exception?)

        timed_out = false
        begin
          byte = @read.not_nil!.read_byte
          timed_out = callback_timed_out?
          if byte.nil?
            error = callback_failure || ProcessHandle::Error::Native.new(
              "registered process wait", "wake pipe closed before process readiness"
            )
          elsif callback_error = callback_failure
            error = callback_error
          end
        rescue ex : IO::Error
          error = callback_failure || ProcessHandle::Error::Native.new(
            "registered process wait wake read", ex.message || ex.class.name
          )
        rescue ex
          error = ex
        ensure
          error ||= cleanup
        end

        raise error.not_nil! if error
        !timed_out
      end

      # Unregister quiescence owns callback-context lifetime. If unregister
      # fails, keep all callback-visible unmanaged state alive rather than risk
      # a callback use-after-free. The resulting exceptional path intentionally
      # leaks that small allocation/handle until the callback/kernel settles.
      private def cleanup : Exception?
        unless @wait_handle.null?
          begin
            Native.unregister_wait_blocking(@wait_handle)
            @wait_handle = LibC::HANDLE.null
          rescue ex
            return ex
          end
        end

        first_error = nil.as(Exception?)
        @context.value.close_write_handle unless @context.null?
        begin
          @read.try &.close
        rescue ex
          first_error ||= ex
        end
        @read = nil

        unless @context.null?
          LibC.free(@context.as(Void*))
          @context = Pointer(CallbackContext).null
        end
        first_error
      end

      private def callback_timed_out? : Bool
        return false if @context.null?
        @context.value.timed_out?
      end

      private def callback_failure : ProcessHandle::Error::Native?
        return nil if @context.null?
        @context.value.failure
      end
    end
  end
{% end %}
