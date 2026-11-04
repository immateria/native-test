# Child program for the Windows standard-stream specs, which cannot count on `cat` or `sh`. Build it and point
# PROCESS_SUPERVISION_STDIO_CHILD at the executable; the specs are pending without it.
#
#   cat          copy standard input to standard output until EOF
#   split        write "out\n" to standard output and "err\n" to standard error
#   tree         start this program again as `ready` with inherited streams, then wait for it
#   ready        write "ready\n" to standard output, then sleep for a minute
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
else
  STDERR.puts "usage: stdio_child cat|split|tree|ready"
  exit 2
end
