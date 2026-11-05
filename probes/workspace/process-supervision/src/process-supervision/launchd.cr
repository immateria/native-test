module ProcessSupervision
  # launchd as the service manager of a supervisor on macOS: a job definition (`JobSpec`, rendered as a property
  # list), and `install` / `uninstall` / `status` / `kickstart` through `launchctl`.
  #
  # What launchd does and does not do for a supervisor (measured on macOS 15 and 26, explore/FINDINGS.md "launchd as
  # the supervisor's own manager"):
  #
  # * on `bootout` it sends SIGTERM, then SIGKILL after `ExitTimeOut` (default 20 s); when the job's main process ends
  #   (also by a crash) it kills the job's **process group**, unless `AbandonProcessGroup`;
  # * it never ends a process that left the group (`setsid`): a supervisor run by launchd still needs its own escapee
  #   handling (`ProcessGroup#escapees`), and should shut its children down before launchd's SIGKILL, which is what
  #   `JobSpec#exit_timeout_for` sizes `ExitTimeOut` for;
  # * `KeepAlive` restarts a job 10 s after it exits by default (`ThrottleInterval` changes that; 1 s measured 1.1 s);
  # * a user's jobs go to `gui/<uid>` (a login session; `user/<uid>` refused bootstrap with EIO on the runners), root's
  #   to `system`.
  #
  # The property list is rendered on every platform; the `launchctl` operations are macOS only.
  module Launchd
    # A launchd job. Only the keys a supervisor needs; `extra` takes verbatim `<key>…</key><value/>` XML for others.
    class JobSpec
      property label : String
      property program_arguments : Array(String)
      property environment : Hash(String, String) = {} of String => String
      property working_directory : String? = nil
      property run_at_load : Bool = true
      # Restart whenever the job exits.
      property keep_alive : Bool = false
      property throttle_interval : Time::Span? = nil
      # Time between launchd's SIGTERM and its SIGKILL on bootout.
      property exit_timeout : Time::Span? = nil
      property abandon_process_group : Bool = false
      property standard_out_path : String? = nil
      property standard_error_path : String? = nil
      # "Background", "Standard", "Adaptive" or "Interactive" (scheduling and resource policy).
      property process_type : String? = nil
      property extra : String? = nil

      def initialize(@label : String, @program_arguments : Array(String))
        raise ArgumentError.new("label must not be empty") if @label.empty?
        raise ArgumentError.new("label must not contain '/'") if @label.includes?('/')
        raise ArgumentError.new("program_arguments must not be empty") if @program_arguments.empty?
      end

      # Sets `ExitTimeOut` so that launchd's SIGKILL comes only after a supervisor's own shutdown (`Group#shutdown`
      # with *grace* and *kill_after*) has finished, plus *margin*.
      def exit_timeout_for(grace : Time::Span, kill_after : Time::Span, margin : Time::Span = 2.seconds) : self
        @exit_timeout = grace + kill_after + margin
        self
      end

      def to_plist : String
        String.build do |io|
          io << %(<?xml version="1.0" encoding="UTF-8"?>\n)
          io << %(<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n)
          io << %(<plist version="1.0">\n<dict>\n)
          key_string(io, "Label", @label)
          io << "  <key>ProgramArguments</key>\n  <array>\n"
          @program_arguments.each { |arg| io << "    <string>" << Launchd.escape(arg) << "</string>\n" }
          io << "  </array>\n"
          unless @environment.empty?
            io << "  <key>EnvironmentVariables</key>\n  <dict>\n"
            @environment.each do |name, value|
              io << "    <key>" << Launchd.escape(name) << "</key><string>" << Launchd.escape(value) << "</string>\n"
            end
            io << "  </dict>\n"
          end
          @working_directory.try { |dir| key_string(io, "WorkingDirectory", dir) }
          key_bool(io, "RunAtLoad", @run_at_load)
          key_bool(io, "KeepAlive", @keep_alive) if @keep_alive
          @throttle_interval.try { |span| key_integer(io, "ThrottleInterval", span.total_seconds.ceil.to_i) }
          @exit_timeout.try { |span| key_integer(io, "ExitTimeOut", span.total_seconds.ceil.to_i) }
          key_bool(io, "AbandonProcessGroup", true) if @abandon_process_group
          @standard_out_path.try { |path| key_string(io, "StandardOutPath", path) }
          @standard_error_path.try { |path| key_string(io, "StandardErrorPath", path) }
          @process_type.try { |type| key_string(io, "ProcessType", type) }
          @extra.try { |xml| io << xml << '\n' }
          io << "</dict>\n</plist>\n"
        end
      end

      private def key_string(io, key, value) : Nil
        io << "  <key>" << key << "</key>\n  <string>" << Launchd.escape(value) << "</string>\n"
      end

      private def key_bool(io, key, value) : Nil
        io << "  <key>" << key << "</key>\n  <" << (value ? "true" : "false") << "/>\n"
      end

      private def key_integer(io, key, value) : Nil
        io << "  <key>" << key << "</key>\n  <integer>" << value << "</integer>\n"
      end
    end

    # What `launchctl print` reports about a loaded job.
    record Status, state : String?, pid : Int64?, last_exit_code : String?, runs : Int32?

    # :nodoc:
    def self.escape(text : String) : String
      text.gsub({'&' => "&amp;", '<' => "&lt;", '>' => "&gt;", '"' => "&quot;", '\'' => "&apos;"})
    end

    # The label launchd started this process under (it sets XPC_SERVICE_NAME for its jobs), or nil.
    def self.current_label : String?
      ENV["XPC_SERVICE_NAME"]?.presence.try { |name| name == "0" ? nil : name }
    end

    # `system` for root, otherwise this user's login-session domain `gui/<uid>`.
    def self.default_domain : String
      {% if flag?(:unix) %}
        uid = LibC.getuid
        uid == 0 ? "system" : "gui/#{uid}"
      {% else %}
        raise Error::Unsupported.new("launchd exists only on macOS")
      {% end %}
    end

    # Where `install` writes the property list: /Library/LaunchDaemons for `system`, ~/Library/LaunchAgents otherwise.
    def self.plist_path(label : String, domain : String = default_domain) : Path
      if domain == "system"
        Path["/Library/LaunchDaemons/#{label}.plist"]
      else
        Path.home / "Library" / "LaunchAgents" / "#{label}.plist"
      end
    end

    # Writes the job's property list and loads it (`launchctl bootstrap`), replacing a loaded job with the same label.
    # Returns the property list's path.
    def self.install(spec : JobSpec, domain : String = default_domain) : Path
      ensure_macos!
      path = plist_path(spec.label, domain)
      Dir.mkdir_p(path.parent)
      launchctl("bootout", "#{domain}/#{spec.label}", allow_failure: true)
      File.write(path, spec.to_plist)
      launchctl("bootstrap", domain, path.to_s)
      path
    end

    # Unloads the job (launchd stops it: SIGTERM, then SIGKILL after `ExitTimeOut`) and deletes its property list.
    # Returns false if no such job was loaded.
    def self.uninstall(label : String, domain : String = default_domain) : Bool
      ensure_macos!
      loaded = launchctl("bootout", "#{domain}/#{label}", allow_failure: true)
      File.delete?(plist_path(label, domain))
      loaded
    end

    # The loaded job's state, or nil when it is not loaded.
    def self.status(label : String, domain : String = default_domain) : Status?
      ensure_macos!
      output = IO::Memory.new
      result = Process.run("launchctl", ["print", "#{domain}/#{label}"], output: output, error: Process::Redirect::Close)
      return nil unless result.success?
      text = output.to_s
      field = ->(name : String) { text[/^\t#{name} = ([^\n]+)$/m, 1]?.try(&.strip) }
      Status.new(field.call("state"), field.call("pid").try(&.to_i64?), field.call("last exit code"),
        field.call("runs").try(&.to_i?))
    end

    # Starts the job now (`launchctl kickstart`); with *kill*, restarts it if it is running.
    def self.kickstart(label : String, domain : String = default_domain, *, kill : Bool = false) : Nil
      ensure_macos!
      args = ["kickstart"]
      args << "-k" if kill
      args << "#{domain}/#{label}"
      launchctl(*args)
    end

    private def self.launchctl(*args : String, allow_failure : Bool = false) : Bool
      output = IO::Memory.new
      result = Process.run("launchctl", args.to_a, output: output, error: output)
      return true if result.success?
      return false if allow_failure
      raise Error::Native.new("launchctl #{args.join(' ')}", output.to_s.strip, result.exit_code.to_i64)
    end

    private def self.ensure_macos! : Nil
      {% unless flag?(:darwin) %}
        raise Error::Unsupported.new("launchd exists only on macOS")
      {% end %}
    end
  end
end
