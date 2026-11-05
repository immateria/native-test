#!/bin/bash
# launchd as the service manager of a supervisor on macOS (explore-hard.yml): which domains a CI user can use, how
# long bootstrap takes to run the job, and what bootout / a crash / KeepAlive do to the job's process tree: the main
# process, a background child in its process group, and a setsid() escapee. Also the coalition launchd puts the job
# in (launchctl procinfo, root). One JSON line per case on stdout; nothing asserts.
#
# Usage: launchd_probe.sh <work dir>
set -u
WORK=$(cd "$1" && pwd)
UIDN=$(id -u)
emit() { printf '{"probe":"launchd","case":"%s",%s}\n' "$1" "$2"; }
# ps, not kill -0: kill -0 answers EPERM for another user's process and succeeds for a zombie
state_of() { local st; st=$(ps -o stat= -p "${1:-0}" 2>/dev/null | tr -d ' '); case "$st" in "") echo gone;; Z*) echo zombie;; *) echo alive;; esac; }
coalition() { sudo launchctl procinfo "$1" 2>/dev/null | grep -iE -A3 'coalition = \{' | grep -iE 'coalition|ID' | tr -s ' \n"\t' ' ' | cut -c1-240; }
ms() { perl -MTime::HiRes=time -e 'printf "%.0f", time*1000'; }

# the job: writes its pid, starts a background sleep (same process group) and a setsid() escapee, then sleeps
cat > "$WORK/job.sh" <<'JOB'
#!/bin/bash
D="$1"
echo $$ > "$D/main.pid"
/bin/sleep 600 &
echo $! > "$D/bg.pid"
/usr/bin/perl -MPOSIX -e 'my $p = fork(); if ($p == 0) { POSIX::setsid(); open(my $f, ">", $ARGV[0]); print $f $$; close $f; exec "/bin/sleep", "601"; } ' "$D/esc.pid"
trap "$2" TERM
while true; do /bin/sleep 1; done
JOB
chmod +x "$WORK/job.sh"

plist() { # label dir term_action extra_xml
  cat <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$1</string>
<key>ProgramArguments</key><array><string>$WORK/job.sh</string><string>$2</string><string>$3</string></array>
<key>RunAtLoad</key><true/>
<key>StandardErrorPath</key><string>$2/stderr.txt</string>
$4
</dict></plist>
PL
}

for d in "gui/$UIDN" "user/$UIDN" "system"; do
  out=$(launchctl print "$d" 2>&1 | head -3 | tr '\n"\\' '   ')
  emit domain_print "\"domain\":\"$d\",\"head\":\"$out\""
done
emit context "\"uid\":$UIDN,\"sw\":\"$(sw_vers -productVersion)\",\"launchctl_version\":\"$(launchctl version 2>&1 | head -1 | tr '"' ' ')\""

run_case() { # name domain sudo term_action extra_xml ending
  local name=$1 domain=$2 su=$3 term=$4 extra=$5 ending=$6
  local label="dev.nativetest.$name.$$"
  local dir="$WORK/$name"
  rm -rf "$dir"; mkdir -p "$dir"; chmod 777 "$dir"
  local plistfile
  if [ "$domain" = system ]; then plistfile="/Library/LaunchDaemons/$label.plist"; else plistfile="$HOME/Library/LaunchAgents/$label.plist"; mkdir -p "$HOME/Library/LaunchAgents"; fi
  plist "$label" "$dir" "$term" "$extra" | $su tee "$plistfile" > /dev/null
  [ "$domain" = system ] && sudo chown root:wheel "$plistfile"
  local t0=$(ms)
  local boot=$($su launchctl bootstrap "$domain" "$plistfile" 2>&1 | tr '\n"\\' '   ')
  local boot_ms=$(( $(ms) - t0 ))
  local i=0
  while [ ! -s "$dir/esc.pid" ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done
  local run_ms=$(( $(ms) - t0 ))
  local main=$(cat "$dir/main.pid" 2>/dev/null) bg=$(cat "$dir/bg.pid" 2>/dev/null) esc=$(cat "$dir/esc.pid" 2>/dev/null)
  local target="$domain/$label"
  local state=$($su launchctl print "$target" 2>&1 | grep -E '^\s*(state|pid|last exit code|runs) =' | tr -s ' \n"' ' ')
  local co_main="" co_bg="" co_esc=""
  [ -n "$main" ] && { co_main=$(coalition "$main"); co_bg=$(coalition "$bg"); co_esc=$(coalition "$esc"); }
  local pgid_main=$(ps -o pgid= -p "${main:-1}" 2>/dev/null | tr -d ' ') pgid_bg=$(ps -o pgid= -p "${bg:-1}" 2>/dev/null | tr -d ' ') pgid_esc=$(ps -o pgid= -p "${esc:-1}" 2>/dev/null | tr -d ' ')
  local t1=$(ms) action="" restarted=""
  case $ending in
    bootout) action=$($su launchctl bootout "$target" 2>&1 | tr '\n"\\' '   ');;
    kill_main) sudo kill -9 "$main";;
    kill_main_keepalive)
      sudo kill -9 "$main"
      i=0; while [ $i -lt 300 ]; do n=$(cat "$dir/main.pid" 2>/dev/null); [ -n "$n" ] && [ "$n" != "$main" ] && break; sleep 0.05; i=$((i+1)); done
      restarted="\"restart_ms\":$(( $(ms) - t1 )),\"new_main\":\"$(cat "$dir/main.pid" 2>/dev/null)\",";;
  esac
  local end_ms=$(( $(ms) - t1 ))
  # when each process is gone (ms after the ending began; -1 = still there after 8 s)
  local g_main=-1 g_bg=-1 g_esc=-1 now
  while :; do
    now=$(( $(ms) - t1 ))
    [ $g_main = -1 ] && [ "$(state_of "$main")" = gone ] && g_main=$now
    [ $g_bg = -1 ] && [ "$(state_of "$bg")" = gone ] && g_bg=$now
    [ $g_esc = -1 ] && [ "$(state_of "$esc")" = gone ] && g_esc=$now
    { [ $g_main != -1 ] && [ $g_bg != -1 ] && [ $g_esc != -1 ]; } && break
    [ $now -gt 8000 ] && break
    sleep 0.05
  done
  emit "$name" "\"domain\":\"$domain\",\"bootstrap\":\"$boot\",\"bootstrap_ms\":$boot_ms,\"running_after_ms\":$run_ms,\"main\":\"$main\",\"bg\":\"$bg\",\"escapee\":\"$esc\",\"pgids\":\"$pgid_main/$pgid_bg/$pgid_esc\",\"print\":\"$state\",\"coalition_main\":\"$co_main\",\"coalition_bg\":\"$co_bg\",\"coalition_escapee\":\"$co_esc\",\"ending\":\"$ending\",\"action\":\"$action\",\"end_ms\":$end_ms,$restarted\"main_gone_ms\":$g_main,\"bg_gone_ms\":$g_bg,\"escapee_gone_ms\":$g_esc,\"escapee_state\":\"$(state_of "$esc")\",\"stderr\":\"$(head -c 300 "$dir/stderr.txt" 2>/dev/null | tr '\n"\\' '   ')\""
  $su launchctl bootout "$target" > /dev/null 2>&1
  for p in $(cat "$dir"/*.pid 2>/dev/null); do sudo kill -9 "$p" 2>/dev/null; done
  $su rm -f "$plistfile"
}

run_case gui_bootout "gui/$UIDN" "" "exit 0" "" bootout
run_case gui_bootout_ignores_term "gui/$UIDN" "" "" "<key>ExitTimeOut</key><integer>3</integer>" bootout
run_case gui_abandon_process_group "gui/$UIDN" "" "exit 0" "<key>AbandonProcessGroup</key><true/>" bootout
run_case gui_main_crash "gui/$UIDN" "" "exit 0" "" kill_main
run_case gui_keepalive "gui/$UIDN" "" "exit 0" "<key>KeepAlive</key><true/>" kill_main_keepalive
run_case gui_keepalive_throttle1 "gui/$UIDN" "" "exit 0" "<key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>1</integer>" kill_main_keepalive
run_case system_bootout system sudo "exit 0" "" bootout
run_case system_main_crash system sudo "exit 0" "" kill_main
run_case system_bootout_ignores_term system sudo "" "<key>ExitTimeOut</key><integer>3</integer>" bootout
run_case system_abandon_process_group system sudo "exit 0" "<key>AbandonProcessGroup</key><true/>" bootout
exit 0
