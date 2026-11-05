abstract class ProcessHandle
  # One process in a system-wide listing. `name` is the short command name the kernel keeps (15 or 16 characters on
  # Linux and macOS, the executable file name on Windows).
  record Entry, pid : Int64, parent_pid : Int64, name : String

  # Every process this user can see, at one moment (point-in-time: entries can be stale as soon as it returns).
  def self.snapshot : Array(Entry)
    {% if flag?(:linux) %}
      entries = [] of Entry
      Dir.each_child("/proc") do |name|
        next unless name.each_char.all?(&.ascii_number?)
        begin
          stat = File.read("/proc/#{name}/stat")
          open = stat.index('(') || next
          close = stat.rindex(')') || next
          fields = stat[close + 2..].split(' ')
          entries << Entry.new(name.to_i64, fields[1].to_i64, stat[open + 1...close])
        rescue File::Error
        end
      end
      entries
    {% elsif flag?(:darwin) %}
      ProcessHandle::Darwin.snapshot
    {% elsif flag?(:win32) %}
      ProcessHandle::Windows.snapshot
    {% else %}
      raise Error::Unsupported.new("process snapshots are not implemented for this target")
    {% end %}
  end

  # The processes descending from *pid* in *entries* (parent-pid links: an orphan reparented to init is not found).
  def self.descendants(pid : Int, entries : Array(Entry) = snapshot) : Array(Entry)
    children = entries.group_by(&.parent_pid)
    found = [] of Entry
    queue = [pid.to_i64]
    while current = queue.shift?
      (children[current]? || [] of Entry).each do |entry|
        next if entry.pid == current
        found << entry
        queue << entry.pid
      end
    end
    found
  end
end
