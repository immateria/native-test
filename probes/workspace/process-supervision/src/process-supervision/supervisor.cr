module ProcessSupervision
  # Bounded capture of a child's output: an `IO` to pass as `output:` / `error:`. Splits what it receives into lines
  # (a line longer than *max_line* bytes is cut there), keeps the last *capacity* of them with a timestamp, and hands
  # each complete line to an optional callback. Memory stays bounded however much the child writes.
  class LineLog < IO
    record Line, at : Time, stream : String, text : String

    getter capacity : Int32
    @on_line : (Line ->)?

    def initialize(@stream : String = "stdout", @capacity : Int32 = 1000, @max_line : Int32 = 65_536,
                   &on_line : Line ->)
      @on_line = on_line
      @lines = Deque(Line).new
      @partial = IO::Memory.new
      @lock = Thread::Mutex.new
    end

    def initialize(@stream : String = "stdout", @capacity : Int32 = 1000, @max_line : Int32 = 65_536)
      @lines = Deque(Line).new
      @partial = IO::Memory.new
      @lock = Thread::Mutex.new
      @on_line = nil
    end

    def lines : Array(Line)
      @lock.synchronize { @lines.to_a }
    end

    def read(slice : Bytes) : Int32
      raise IO::Error.new("LineLog is write-only")
    end

    def write(slice : Bytes) : Nil
      completed = [] of Line
      @lock.synchronize do
        slice.each do |byte|
          if byte == '\n'.ord
            completed << take_line
          else
            @partial.write_byte(byte) if @partial.size < @max_line
          end
        end
      end
      completed.each { |line| @on_line.try &.call(line) }
    end

    # Keeps a final line that had no newline.
    def flush : Nil
      line = @lock.synchronize { @partial.size > 0 ? take_line : nil }
      line.try { |value| @on_line.try &.call(value) }
    end

    def close : Nil
      flush
      super
    end

    private def take_line : Line
      line = Line.new(Time.utc, @stream, String.new(@partial.to_slice))
      @partial.clear
      @lines << line
      while @lines.size > @capacity
        @lines.shift
      end
      line
    end
  end

  # A process supervisor in the style of systemd, s6 and Erlang/OTP, built on `ProcessSupervision.spawn` (each service
  # gets the strongest containment the host offers):
  #
  # * restart policy per service (never / on failure / always) with exponential backoff and jitter, and a restart
  #   intensity limit (at most *max_restarts* in *restart_window*, then the service is given up);
  # * readiness: `Readiness::Notify` gives the service a `NOTIFY_SOCKET` (systemd's sd_notify protocol: `READY=1`,
  #   `STATUS=...`, `WATCHDOG=1`); a service that is not ready within *ready_timeout* is restarted;
  # * watchdog: with *watchdog* set, a notify service that does not send `WATCHDOG=1` within that interval is restarted;
  # * logs: stdout and stderr go to a bounded `LineLog` per service;
  # * dependencies: a service starts after those it depends on are ready (or started, without readiness);
  # * events: every state change is published on `#events` (a buffered channel; when it is full, events are dropped
  #   rather than blocking a service).
  #
  # Experimental: the API shape is a first cut.
  class Supervisor
    enum Restart
      Never
      OnFailure
      Always
    end

    enum Readiness
      # ready as soon as the process exists
      None
      # ready when the service sends READY=1 to NOTIFY_SOCKET (Linux and macOS)
      Notify
    end

    enum EventKind
      Starting
      Started
      Ready
      Status
      Log
      Unhealthy
      Exited
      Restarting
      GaveUp
      Stopped
    end

    record Event, service : String, kind : EventKind, detail : String = "", outcome : ExitOutcome? = nil,
      pid : Int64? = nil, at : Time = Time.utc

    class Spec
      property name : String
      property command : String
      property args : Array(String) = [] of String
      property env : Hash(String, String?) = {} of String => String?
      property chdir : String? = nil
      property restart : Restart = Restart::OnFailure
      property backoff_min : Time::Span = 100.milliseconds
      property backoff_max : Time::Span = 30.seconds
      property max_restarts : Int32 = 5
      property restart_window : Time::Span = 60.seconds
      property readiness : Readiness = Readiness::None
      property ready_timeout : Time::Span = 30.seconds
      property watchdog : Time::Span? = nil
      property stop_grace : Time::Span = 5.seconds
      property kill_after : Time::Span = 2.seconds
      property depends_on : Array(String) = [] of String
      property log_lines : Int32 = 1000
      property log_events : Bool = false
      property options : SpawnOptions = SpawnOptions.new

      def initialize(@name : String, @command : String, @args : Array(String) = [] of String)
      end
    end

    enum State
      Pending
      Starting
      Running
      Ready
      Backoff
      Stopped
      Failed
    end

    # Run-time state of one service.
    class Service
      getter spec : Spec
      getter state : State = State::Pending
      getter restarts : Int32 = 0
      getter last_outcome : ExitOutcome? = nil
      getter status_text : String = ""
      getter log : LineLog
      getter pid : Int64? = nil

      @ready = Channel(Nil).new(1)
      @child : Child? = nil
      @last_watchdog = Time.instant

      def initialize(@spec : Spec, @log : LineLog)
      end

      protected setter state, restarts, last_outcome, status_text, pid, child
      protected getter ready
      protected getter child
      protected property last_watchdog
    end

    getter events = Channel(Event).new(1024)

    @services = {} of String => Service
    @order = [] of String
    @stopping = Atomic(Bool).new(false)
    @finished = Channel(String).new(64)
    @running = 0

    def add(spec : Spec) : Service
      raise ArgumentError.new("service #{spec.name} exists") if @services.has_key?(spec.name)
      spec.depends_on.each do |dependency|
        raise ArgumentError.new("#{spec.name} depends on unknown service #{dependency}") unless @services.has_key?(dependency)
      end
      log = LineLog.new("output", spec.log_lines)
      service = Service.new(spec, log)
      @services[spec.name] = service
      @order << spec.name
      service
    end

    def [](name : String) : Service
      @services[name]
    end

    def services : Array(Service)
      @order.map { |name| @services[name] }
    end

    # Starts every service in its own fiber (dependencies first) and returns at once.
    def start : Nil
      @order.each do |name|
        service = @services[name]
        @running += 1
        spawn(name: "supervisor-#{name}") do
          begin
            service.spec.depends_on.each { |dependency| wait_ready(@services[dependency]) }
            run(service) unless @stopping.get
          ensure
            @finished.send(name)
          end
        end
      end
    end

    # Stops every service (reverse order: graceful stop, then kill) and waits for the service fibers to end.
    def stop : Nil
      @stopping.set(true)
      @order.reverse_each do |name|
        service = @services[name]
        service.child.try do |child|
          child.group.stop(grace: service.spec.stop_grace, kill_after: service.spec.kill_after, close: false) rescue nil
        end
      end
      @running.times { @finished.receive }
      @running = 0
    end

    private def run(service : Service) : Nil
      spec = service.spec
      starts = Deque(Time::Instant).new
      backoff = spec.backoff_min
      loop do
        break if @stopping.get
        service.state = State::Starting
        emit(service, EventKind::Starting)
        started_at = Time.instant
        outcome = run_once(service)
        service.last_outcome = outcome
        service.pid = nil
        emit(service, EventKind::Exited, outcome.try(&.description) || "could not start", outcome)
        break if @stopping.get

        failed = outcome.nil? || !outcome.success?
        restart = case spec.restart
                  in .never?      then false
                  in .on_failure? then failed
                  in .always?     then true
                  end
        unless restart
          service.state = failed ? State::Failed : State::Stopped
          break
        end

        now = Time.instant
        starts << now
        while (first = starts.first?) && now - first > spec.restart_window
          starts.shift
        end
        if starts.size > spec.max_restarts
          service.state = State::Failed
          emit(service, EventKind::GaveUp, "#{starts.size} restarts within #{spec.restart_window}")
          break
        end

        # a run that lasted a whole window resets the backoff
        backoff = spec.backoff_min if now - started_at > spec.restart_window
        delay = backoff * (0.8 + Random.rand * 0.4)
        service.state = State::Backoff
        service.restarts += 1
        emit(service, EventKind::Restarting, "in #{delay.total_milliseconds.round.to_i} ms")
        sleep_unless_stopping(delay)
        backoff = {backoff * 2, spec.backoff_max}.min
      end
      service.state = State::Stopped if @stopping.get
      emit(service, EventKind::Stopped)
    end

    # One run of the service: spawn, readiness, watchdog, wait. nil when it could not be started.
    private def run_once(service : Service) : ExitOutcome?
      spec = service.spec
      env = spec.env.dup
      notify = spec.readiness.notify? || !spec.watchdog.nil? ? NotifySocket.open : nil
      notify.try { |socket| env["NOTIFY_SOCKET"] = socket.path }
      spec.watchdog.try { |interval| env["WATCHDOG_USEC"] = interval.total_microseconds.to_i64.to_s }
      sink = spec.log_events ? LineLog.new("output", 1) { |line| emit(service, EventKind::Log, line.text) } : nil
      output = sink ? MultiSink.new(service.log, sink) : service.log
      child = begin
        ProcessSupervision.spawn(spec.command, spec.args, env: env, chdir: spec.chdir, input: ::Process::Redirect::Close,
          output: output, error: output, options: spec.options)
      rescue ex
        notify.try &.close
        emit(service, EventKind::Exited, "spawn failed: #{ex.message}")
        return nil
      end
      service.child = child
      service.pid = child.pid
      service.state = State::Running
      service.last_watchdog = Time.instant
      emit(service, EventKind::Started, pid: child.pid)

      done = Channel(Nil).new(1)
      if socket = notify
        spawn(name: "supervisor-notify-#{spec.name}") { listen(service, socket, done) }
      end
      if spec.readiness.none?
        mark_ready(service)
      else
        spawn(name: "supervisor-ready-#{spec.name}") do
          select
          when done.receive?
          when timeout(spec.ready_timeout)
            unless service.state.ready?
              emit(service, EventKind::Unhealthy, "not ready after #{spec.ready_timeout}")
              child.group.stop(grace: spec.stop_grace, kill_after: spec.kill_after, close: false) rescue nil
            end
          end
        end
      end
      if interval = spec.watchdog
        spawn(name: "supervisor-watchdog-#{spec.name}") { watch(service, child, interval, done) }
      end

      status = begin
        child.wait
      rescue ex
        child.status
      end
      done.close
      # end anything the service left behind in its group
      child.group.shutdown(grace: spec.stop_grace, kill_after: spec.kill_after) rescue nil
      child.close rescue nil
      notify.try &.close
      service.child = nil
      status.try { |value| ExitOutcome.classify(value) }
    end

    private def listen(service : Service, socket : NotifySocket, done : Channel(Nil)) : Nil
      loop do
        message = socket.receive(done)
        break unless message
        message.each_line do |line|
          key, _, value = line.partition('=')
          case key
          when "READY"    then mark_ready(service) if value == "1"
          when "STATUS"   then service.status_text = value; emit(service, EventKind::Status, value)
          when "WATCHDOG" then service.last_watchdog = Time.instant if value == "1"
          end
        end
      end
    end

    private def watch(service : Service, child : Child, interval : Time::Span, done : Channel(Nil)) : Nil
      loop do
        select
        when done.receive?
          return
        when timeout(interval / 4)
        end
        if Time.instant - service.last_watchdog > interval
          emit(service, EventKind::Unhealthy, "no WATCHDOG=1 within #{interval}")
          child.group.stop(grace: service.spec.stop_grace, kill_after: service.spec.kill_after, close: false) rescue nil
          return
        end
      end
    end

    private def mark_ready(service : Service) : Nil
      return if service.state.ready?
      service.state = State::Ready
      emit(service, EventKind::Ready, pid: service.pid)
      select
      when service.ready.send(nil)
      else
      end
    end

    private def wait_ready(service : Service) : Nil
      loop do
        return if service.state.ready? || service.state.failed? || service.state.stopped? || @stopping.get
        select
        when service.ready.receive
          service.ready.send(nil) rescue nil # leave the signal for other dependants
          return
        when timeout(100.milliseconds)
        end
      end
    end

    private def sleep_unless_stopping(span : Time::Span) : Nil
      deadline = Time.instant + span
      until @stopping.get || Time.instant >= deadline
        sleep({deadline - Time.instant, 50.milliseconds}.min)
      end
    end

    private def emit(service : Service, kind : EventKind, detail : String = "", outcome : ExitOutcome? = nil,
                     pid : Int64? = nil) : Nil
      event = Event.new(service.spec.name, kind, detail, outcome, pid || service.pid)
      select
      when @events.send(event)
      else
      end
    end

    # Writes to several IOs (the service log and the event-emitting sink).
    private class MultiSink < IO
      @targets : Array(IO)

      def initialize(*targets : IO)
        @targets = targets.to_a.map(&.as(IO))
      end

      def read(slice : Bytes) : Int32
        raise IO::Error.new("write-only")
      end

      def write(slice : Bytes) : Nil
        @targets.each(&.write(slice))
      end

      def flush : Nil
        @targets.each(&.flush)
      end
    end

    # The receiving end of systemd's notification protocol: a datagram socket whose path is given to the service as
    # NOTIFY_SOCKET; each datagram is newline-separated KEY=VALUE pairs.
    class NotifySocket
      getter path : String

      def self.open : NotifySocket
        {% if flag?(:unix) %}
          base = Dir.tempdir
          # sockaddr_un paths are limited to 104-108 bytes; macOS's per-user temp directory is long
          base = "/tmp" if base.bytesize > 60
          path = File.join(base, "ps-notify-#{::Process.pid}-#{Random.new.hex(6)}.sock")
          socket = ::Socket.unix(::Socket::Type::DGRAM)
          socket.bind(::Socket::UNIXAddress.new(path))
          new(path, socket)
        {% else %}
          raise Error::Unsupported.new("sd_notify readiness needs Unix-domain datagram sockets")
        {% end %}
      end

      def initialize(@path : String, @socket : ::Socket)
      end

      # The next message, or nil once *done* is closed.
      def receive(done : Channel(Nil)) : String?
        buffer = Bytes.new(4096)
        loop do
          return nil if done.closed?
          @socket.read_timeout = 100.milliseconds
          begin
            count = @socket.read(buffer)
            return String.new(buffer[0, count])
          rescue IO::TimeoutError
          rescue IO::Error
            return nil
          end
        end
      end

      def close : Nil
        @socket.close rescue nil
        File.delete?(@path) rescue nil
      end
    end
  end
end
