module ProcessSupervision
  # Ends a group when the supervisor dies, however it dies (SIGKILL, a crash, the OOM killer), on systems with no
  # kernel kill-on-close for it. A small watcher (`/bin/sh`) blocks reading a pipe whose only writer is this process;
  # when the supervisor exits, the kernel closes that writer, the read returns end-of-file and the watcher kills the
  # group (`kill -KILL -<pgid>`, or `cgroup.kill`). `disarm` tells it to exit without killing.
  #
  # Measured (explore/FINDINGS.md, "Detecting that the supervisor died"): a lifeline pipe reports the supervisor's death
  # within 0.1-0.3 ms on Linux and 0.4-1.1 ms on macOS. A Windows Job is already kill-on-close, so arming one is a no-op.
  # Escapees of a process group (a descendant that called setsid) are not reached by the watcher; a cgroup has none.
  class Lifeline
    getter watcher : Child?

    def self.arm(group : Group) : Lifeline
      {% if flag?(:unix) %}
        script = argument = nil.as(String?)
        if group.is_a?(POSIX::ProcessGroup)
          script = %q(IFS= read -r line; [ "$line" = disarm ] && exit 0; kill -KILL -"$1")  # no "--": dash rejects it
          argument = group.pgid.to_s
        end
        {% if flag?(:linux) %}
          if group.is_a?(Linux::CgroupV2)
            script = %q(IFS= read -r line; [ "$line" = disarm ] && exit 0; echo 1 > "$1/cgroup.kill")
            argument = group.path.to_s
          end
        {% end %}
        return new(nil) unless script && argument
        options = SpawnOptions.new
        options.new_session = true
        watcher = POSIX::ProcessGroup.spawn_leader("/bin/sh", ["-c", script, "sh", argument],
          input: ::Process::Redirect::Pipe, output: ::Process::Redirect::Close, error: ::Process::Redirect::Close,
          track_descendants: false, options: options)
        new(watcher)
      {% else %}
        new(nil)
      {% end %}
    end

    def initialize(@watcher : Child?)
    end

    def armed? : Bool
      if watcher = @watcher
        watcher.status.nil? && watcher.handle.alive?
      else
        false
      end
    end

    # Tells the watcher to exit without killing, and waits for it.
    def disarm : Nil
      watcher = @watcher
      return unless watcher
      @watcher = nil
      begin
        watcher.input.puts "disarm"
        watcher.input.close
      rescue IO::Error
      end
      watcher.wait(5.seconds)
      watcher.close
      watcher.group.close
    end
  end
end
