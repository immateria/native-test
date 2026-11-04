# Diagnose what a filtered (unelevated) token can and cannot launch. Run THROUGH
# `job_explore.exe launch-unelevated -- pwsh -NoProfile -File unelevated-diag.ps1`.
# Writes explore-out\unelevated-diag.txt; every probe is independent.
$out = Join-Path $PSScriptRoot "..\..\explore-out\unelevated-diag.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
"" | Set-Content $out

function Probe([string]$Name, [scriptblock]$Body) {
  try {
    $text = (& $Body 2>&1 | Out-String).Trim()
    "[$Name] ok`n$text`n" | Add-Content $out
  } catch {
    "[$Name] FAIL: $($_.Exception.GetType().Name): $($_.Exception.Message)`n" | Add-Content $out
  }
}

Probe "token groups (attributes show deny-only)" { whoami /groups /fo list | Select-String "Group Name|Attributes" | Select-Object -First 24 }
Probe "token privileges" { whoami /priv /fo csv /nh }
Probe "integrity label of crystal.exe"  { icacls C:\crystal\crystal.exe }
Probe "cmd.exe child"                   { cmd /c echo hello-from-cmd }
Probe "git.exe from Program Files"      { & "C:\Program Files\Git\bin\git.exe" --version }
Probe "crystal via & and PATH"          { & crystal --version }
Probe "crystal via full path"           { & C:\crystal\crystal.exe --version }
Probe "crystal via cmd /c"              { cmd /c "C:\crystal\crystal.exe --version" }
Probe "crystal via Start-Process"       { $p = Start-Process C:\crystal\crystal.exe -ArgumentList "--version" -Wait -PassThru -NoNewWindow; "exit=$($p.ExitCode)" }
Probe "open crystal.exe for read"       { $s = [IO.File]::OpenRead("C:\crystal\crystal.exe"); "read ok, length=$($s.Length)"; $s.Dispose() }
Probe "open crystal.exe for execute-ish (share read)" { $s = [IO.File]::Open("C:\crystal\crystal.exe", "Open", "Read", "ReadWrite"); "ok"; $s.Dispose() }
Probe "copy crystal tree to D: then run" {
  $dst = Join-Path $env:RUNNER_TEMP "crystal-copy"
  Copy-Item C:\crystal $dst -Recurse -Force
  & (Join-Path $dst "crystal.exe") --version
}
Probe "cl.exe (MSVC)"                   { & cl 2>&1 | Select-Object -First 1 }
Probe "powershell.exe 5.1 child"        { powershell -NoProfile -Command "'ps51 ok'" }
