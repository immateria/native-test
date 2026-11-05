module ProcessSupervision
  # :nodoc:
  #
  # Waits for a descriptor to become readable through the runtime's event loop (epoll / kqueue / io_uring), so a wait
  # costs nothing while nothing happens instead of waking every few milliseconds.
  module Readiness
    # true when *io* became readable, false when *timeout* expired first (nil waits without limit).
    def self.wait_readable(io : IO::FileDescriptor, timeout : Time::Span?) : Bool
      io.read_timeout = timeout
      Crystal::EventLoop.current.wait_readable(io)
      true
    rescue IO::TimeoutError
      false
    end

    # Polls *condition* with a growing interval (5 ms doubling up to 100 ms): for states the kernel offers no
    # notification for (a POSIX process group becoming empty, a Windows Job's process count).
    def self.poll(timeout : Time::Span?, & : -> Bool) : Bool
      deadline = timeout.try { |span| Time.instant + span }
      interval = 5.milliseconds
      loop do
        return true if yield
        if deadline
          remaining = deadline - Time.instant
          return false if remaining <= Time::Span.zero
          sleep({remaining, interval}.min)
        else
          sleep interval
        end
        interval = {interval * 2, 100.milliseconds}.min
      end
    end
  end
end
