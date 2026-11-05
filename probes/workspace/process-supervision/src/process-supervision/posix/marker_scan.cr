{% if flag?(:darwin) %}
  @[Link("proc")]
  private lib LibProcessSupervisionMarker
    fun proc_listallpids(buffer : Void*, size : Int32) : Int32
    fun sysctl(name : Int32*, namelen : UInt32, oldp : Void*, oldlenp : LibC::SizeT*, newp : Void*, newlen : LibC::SizeT) : Int32
  end
{% end %}

{% if flag?(:unix) %}
  module ProcessSupervision::POSIX
    # :nodoc:
    #
    # Finds the processes that carry a process group's environment marker: the children spawned into the group get
    # `PROCESS_SUPERVISION_GROUP=<token>`, and every program they exec inherits it unless it clears or rewrites its
    # environment. That finds a descendant that left the group (setsid, a double fork reparented to init), which neither
    # signalling the group nor walking parent pids or kernel child lists does. Measured natively (explore/FINDINGS.md,
    # "Finding the descendants of a process"): Linux reads `/proc/<pid>/environ` (about 1 ms for ~200 processes), macOS
    # reads each process's original environment with `sysctl(KERN_PROCARGS2)` (11 ms on arm64, up to 150 ms on Intel for
    # 400-500 processes). Only processes of the same user are readable, which are the only ones a supervisor could signal.
    module MarkerScan
      VARIABLE = "PROCESS_SUPERVISION_GROUP"

      def self.new_token : String
        "#{::Process.pid}-#{Random::Secure.hex(8)}"
      end

      def self.entry(token : String) : String
        "#{VARIABLE}=#{token}"
      end

      # Every process other than this one whose environment carries *token*.
      def self.scan(token : String) : Array(Int64)
        entry = entry(token)
        found = [] of Int64
        own = ::Process.pid.to_i64
        each_pid do |pid|
          next if pid == own
          found << pid if marked?(pid, entry)
        end
        found
      end

      def self.marked?(pid : Int64, entry : String) : Bool
        environment(pid).try(&.includes?(entry)) || false
      end

      {% if flag?(:linux) %}
        private def self.each_pid(&) : Nil
          Dir.each_child("/proc") do |name|
            next unless name.each_char.all?(&.ascii_number?)
            yield name.to_i64
          end
        end

        private def self.environment(pid : Int64) : Array(String)?
          File.read("/proc/#{pid}/environ").split('\0')
        rescue File::Error | IO::Error
          nil
        end
      {% elsif flag?(:darwin) %}
        private CTL_KERN       =  1
        private KERN_ARGMAX    =  8
        private KERN_PROCARGS2 = 49

        private def self.each_pid(&) : Nil
          count = LibProcessSupervisionMarker.proc_listallpids(Pointer(Void).null, 0)
          return if count <= 0
          pids = Array(Int32).new(count + 64, 0)
          count = LibProcessSupervisionMarker.proc_listallpids(pids.to_unsafe.as(Void*), pids.size * sizeof(Int32))
          return if count <= 0
          count.times { |index| yield pids[index].to_i64 if pids[index] > 0 }
        end

        private def self.argmax : Int32
          value = 0
          size = LibC::SizeT.new(sizeof(Int32))
          mib = StaticArray[CTL_KERN, KERN_ARGMAX]
          if LibProcessSupervisionMarker.sysctl(mib.to_unsafe, 2, pointerof(value).as(Void*), pointerof(size), Pointer(Void).null, 0) != 0 || value <= 0
            return 1_048_576
          end
          value
        end

        # KERN_PROCARGS2: argc (Int32), the executable path, NUL padding, argc argument strings, then the environment
        # strings, each NUL-terminated, up to an empty string. Other users' processes answer EINVAL.
        private def self.environment(pid : Int64) : Array(String)?
          buffer = Bytes.new(argmax)
          size = LibC::SizeT.new(buffer.size)
          mib = StaticArray[CTL_KERN, KERN_PROCARGS2, pid.to_i32]
          return nil unless LibProcessSupervisionMarker.sysctl(mib.to_unsafe, 3, buffer.to_unsafe.as(Void*), pointerof(size), Pointer(Void).null, 0) == 0
          data = buffer[0, size.to_i]
          return nil if data.size < 4
          argc = data.to_unsafe.as(Int32*).value
          position = 4
          # the executable path, then its padding
          while position < data.size && data[position] != 0
            position += 1
          end
          while position < data.size && data[position] == 0
            position += 1
          end
          strings = [] of String
          while position < data.size
            finish = position
            while finish < data.size && data[finish] != 0
              finish += 1
            end
            break if finish == position
            strings << String.new(data[position, finish - position])
            position = finish + 1
          end
          strings.size > argc ? strings[argc..] : [] of String
        end
      {% else %}
        private def self.each_pid(&) : Nil
        end

        private def self.environment(pid : Int64) : Array(String)?
          nil
        end
      {% end %}
    end
  end
{% end %}
