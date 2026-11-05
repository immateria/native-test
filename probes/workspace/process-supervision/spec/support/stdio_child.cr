# Child program for the Windows standard-stream specs, which cannot count on `cat` or `sh`. Build it and point
# PROCESS_SUPERVISION_STDIO_CHILD at the executable; the specs are pending without it.
#
#   cat          copy standard input to standard output until EOF
#   split        write "out\n" to standard output and "err\n" to standard error
#   tree         start this program again as `ready` with inherited streams, then wait for it
#   ready        write "ready\n" to standard output, then sleep for a minute
#   break        like ready, but exit 0 (printing "stopping") on a console Ctrl+Break / Ctrl+C
#   crash        fault (access violation)
#   write-handle write "via handle\n" to the inherited handle announced for descriptor 5
case ARGV[0]?
when "cat"
  IO.copy(STDIN, STDOUT)
when "split"
  STDOUT.print "out\n"
  STDERR.print "err\n"
when "tree"
  Process.new(Process.executable_path.not_nil!, ["ready"], input: Process::Redirect::Inherit,
    output: Process::Redirect::Inherit, error: Process::Redirect::Inherit).wait
when "ready"
  STDOUT.print "ready\n"
  STDOUT.flush
  sleep 60.seconds
when "break"
  # waits for a console Ctrl+Break / Ctrl+C (Process.on_terminate), then says so and exits 0
  Process.on_terminate do |reason|
    STDOUT.print "stopping #{reason}\n"
    STDOUT.flush
    exit 0
  end
  STDOUT.print "ready\n"
  STDOUT.flush
  sleep 60.seconds
when "crash"
  # an access violation
  Pointer(Int32).new(16_u64).value = 1
when "write-handle"
  # writes to the handle the parent passed as extra descriptor 5 (PROCESS_SUPERVISION_HANDLES=5:<value>)
  entry = (ENV["PROCESS_SUPERVISION_HANDLES"]? || "").split(',').find(&.starts_with?("5:"))
  abort "no handle 5 in #{ENV["PROCESS_SUPERVISION_HANDLES"]?.inspect}" unless entry
  io = IO::FileDescriptor.new(entry.split(":")[1].to_u64, blocking: true)
  io.print "via handle\n"
  io.flush
else
  STDERR.puts "usage: stdio_child cat|split|tree|ready|break|crash|write-handle"
  exit 2
end
