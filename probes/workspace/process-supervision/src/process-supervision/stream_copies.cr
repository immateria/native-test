module ProcessSupervision
  # :nodoc:
  #
  # Copies between caller-supplied `IO` objects that are not file descriptors (an `IO::Memory`, a socket wrapper, a
  # compressed stream) and pipes connected to a child's standard streams, one fiber per stream, the way the stdlib's
  # `Process` does. The spawn engines create the pipes; `start` runs once the process exists; `Child#wait` calls `wait`,
  # so the caller's output IO is complete when the child's status is returned.
  #
  # Differences from the stdlib, all about not hanging a supervisor on a stream:
  #
  # * a child that exits without reading all of its input is not an error (the copy into its stdin sees a broken pipe
  #   and stops);
  # * once the child has exited, the copy into its stdin is abandoned (its pipe is closed): a source that never ends
  #   (a terminal, a socket) would otherwise keep `wait` blocked forever;
  # * an output pipe reaches end-of-file only when *every* process holding its write end has closed it, so a
  #   grandchild that inherited stdout (`sh -c 'daemon &'`) keeps it open after the child exited. With `wait_delay`
  #   (`SpawnOptions#wait_delay`, as Go's `Cmd.WaitDelay`), `wait` waits that long after the exit, then closes the
  #   pipes and returns; `cut?` tells that output may be missing.
  class StreamCopies
    private record Job, source : IO, target : IO, close_source : Bool, close_target : Bool, into_child : Bool

    @jobs = [] of Job
    @pipes = [] of IO::FileDescriptor
    @input_pipes = [] of IO::FileDescriptor
    @results = Channel({Bool, Exception?}).new(3)
    @outputs = 0
    @cut = false
    property wait_delay : Time::Span? = nil
    @lock = Thread::Mutex.new
    @started = 0
    @waited = false
    @first_error : Exception? = nil
    @closed = Atomic(Bool).new(false)

    # caller's *source* -> *pipe* (the parent's end of the child's stdin pipe), which is closed at EOF of *source*
    def add_input(source : IO, pipe : IO::FileDescriptor) : Nil
      @pipes << pipe
      @input_pipes << pipe
      @jobs << Job.new(source, pipe, false, true, true)
    end

    # *pipe* (the parent's end of the child's stdout/stderr pipe) -> caller's *target*, until the child side closes
    def add_output(pipe : IO::FileDescriptor, target : IO) : Nil
      @pipes << pipe
      @outputs += 1
      @jobs << Job.new(pipe, target, true, false, false)
    end

    def empty? : Bool
      @jobs.empty?
    end

    # Starts one copy fiber per stream. Called once, after the process exists.
    def start : Nil
      jobs = @lock.synchronize do
        taken = @jobs
        @jobs = [] of Job
        @started += taken.size
        taken
      end
      jobs.each do |job|
        spawn(name: "process-supervision-stream-copy") { copy(job) }
      end
    end

    # Called once the child has exited: abandons the copy into its stdin, waits for the output copies (at most
    # `wait_delay`, then closes their pipes) and returns the first error, or nil. Later calls return the same outcome.
    def wait : Exception?
      outputs = @lock.synchronize do
        return @first_error if @waited
        @waited = true
        @started > 0 ? @outputs : 0
      end
      @input_pipes.each { |pipe| pipe.close rescue nil }
      first = nil.as(Exception?)
      deadline = @wait_delay.try { |delay| Time.instant + delay }
      done = 0
      while done < outputs
        result = if deadline
                   remaining = deadline - Time.instant
                   select
                   when value = @results.receive
                     value
                   when timeout(remaining > Time::Span.zero ? remaining : Time::Span.zero)
                     nil
                   end
                 else
                   @results.receive
                 end
        unless result
          # a descendant still holds an output pipe: stop waiting for it
          @cut = true
          close
          break
        end
        into_child, failure = result
        next if into_child
        done += 1
        first ||= failure
      end
      @lock.synchronize { @first_error = first }
      first
    end

    # Whether `wait` gave up on an output stream after `wait_delay` (so the caller's output IO may be incomplete).
    def cut? : Bool
      @cut
    end

    # Closes the parent's pipe ends. Before `start` (a failed spawn) nothing else holds them; after it, a copy that is
    # still running stops with an error that is discarded.
    def close : Nil
      @closed.set(true)
      @pipes.each { |pipe| pipe.close rescue nil }
    end

    private def copy(job : Job) : Nil
      close_source = job.close_source
      close_target = job.close_target
      begin
        IO.copy(job.source, job.target)
        job.target.flush unless job.close_target
        # close here, before reporting, so that a close error is reported and EOF reaches the child first
        job.source.close if close_source
        close_source = false
        job.target.close if close_target
        close_target = false
        @results.send({job.into_child, nil.as(Exception?)})
      rescue ex
        ignored = @closed.get || (job.into_child && broken_pipe?(ex))
        @results.send({job.into_child, ignored ? nil : ex.as(Exception?)})
      ensure
        if close_source
          job.source.close rescue nil
        end
        if close_target
          job.target.close rescue nil
        end
      end
    end

    private def broken_pipe?(ex : Exception) : Bool
      return false unless ex.is_a?(IO::Error)
      {% if flag?(:win32) %}
        ex.os_error.in?(WinError::ERROR_BROKEN_PIPE, WinError::ERROR_NO_DATA)
      {% else %}
        ex.os_error == Errno::EPIPE
      {% end %}
    end
  end
end
