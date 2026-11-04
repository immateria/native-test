# PowerShell 5.1+; run without elevation on native Windows with Crystal 1.21.1+.
# This script always preserves build/runtime diagnostics for the handback.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$Run = Join-Path $Root "windows-probe-output"
$BuildDir = Join-Path $Root ".build"
$ChildDir = Join-Path $Run "child-artifacts"
$Manifest = Join-Path $Root "MANIFEST.sha256"
# A repeated run must never inherit old JSONL, build logs or child markers.
if (Test-Path -LiteralPath $Run) {
  $attrs = (Get-Item -LiteralPath $Run -Force).Attributes
  if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing redirected result directory: $Run"
  }
  Remove-Item -LiteralPath $Run -Recurse -Force
}
# PowerShell 5.1 native coverage verifier: no new Windows runtime dependency.
function Assert-CompleteWindowsResults {
  param([string]$CoveragePath, [string]$ResultsPath)
  if (!(Test-Path -LiteralPath $ResultsPath -PathType Leaf)) { throw "Missing Windows results: $ResultsPath" }
  $Names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  $InWindows = $false
  foreach ($line in (Get-Content -LiteralPath $CoveragePath -Encoding UTF8)) {
    if ($line.StartsWith('## ')) { $InWindows = $line.StartsWith('## Windows Crystal ') }
    elseif ($InWindows -and $line.StartsWith('- `')) {
      if ($line -cnotmatch '^- `([^`]+)`$') { throw "Malformed Windows coverage entry: $line" }
      if (!$Names.Add($Matches[1])) { throw "Duplicate coverage declaration: $($Matches[1])" }
    }
  }
  if ($Names.Count -eq 0) { throw 'Empty Windows coverage ledger' }
  $Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  $Body = 0; $Failures = 0; $Skips = 0; $Summary = $null
  $Lines = @(Get-Content -LiteralPath $ResultsPath -Encoding UTF8)
  foreach ($line in $Lines) {
    if ([string]::IsNullOrWhiteSpace($line)) { throw 'Empty JSONL record' }
    $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop
    if ($record.schema -ne 1 -or $record.platform -ne 'windows' -or $record.checkpoint -ne '0009') { throw 'Wrong record schema, platform or checkpoint' }
    if ($record.case -eq 'summary') {
      if ($null -ne $Summary) { throw 'Duplicate summary' }
      $Summary = $record
      continue
    }
    if ($null -ne $Summary) { throw 'Summary was not last' }
    if ($record.status -cnotin @('pass','fail','error','skip','info')) { throw "Invalid result status: $($record.status)" }
    $Body++
    if ($record.status -cin @('fail','error')) { $Failures++ }
    if ($record.status -ceq 'skip') { $Skips++ }
    if ($Names.Contains([string]$record.case)) {
      if (!$Seen.Add([string]$record.case)) { throw "Duplicate result: $($record.case)" }
      if ($record.status -cne 'pass') { throw "Nonpassing case: $($record.case)=$($record.status)" }
    } elseif ($record.status -cne 'info') {
      throw "Unexpected result: $($record.case)"
    }
  }
  if ($null -eq $Summary) { throw 'Missing final summary' }
  if ($Seen.Count -ne $Names.Count) { throw "Incomplete coverage: got $($Seen.Count) expected $($Names.Count)" }
  if ($Failures -ne 0 -or $Skips -ne 0 -or $Summary.status -cne 'pass') { throw 'Nonpassing summary or diagnostic records' }
  if ([string]$Summary.details.cases -cne [string]$Body -or
      [string]$Summary.details.failures -cne [string]$Failures -or
      [string]$Summary.details.skips -cne [string]$Skips) { throw 'Summary counters contradict recorded results' }
  return $Seen.Count
}
$ExitCode = 0
New-Item -ItemType Directory -Force -Path $Run,$ChildDir | Out-Null
$Report = Join-Path $Run "environment.txt"
"probe=windows-0009-r12" | Set-Content -Encoding UTF8 $Report
"probe_revision=12" | Add-Content $Report
"os_version=$([Environment]::OSVersion.VersionString)" | Add-Content $Report
"processor_architecture=$env:PROCESSOR_ARCHITECTURE" | Add-Content $Report
"processor_count=$([Environment]::ProcessorCount)" | Add-Content $Report
try {
  $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  "os_caption=$($osInfo.Caption)" | Add-Content $Report
  "os_build=$($osInfo.BuildNumber)" | Add-Content $Report
  "os_version_cim=$($osInfo.Version)" | Add-Content $Report
} catch {
  "os_cim=unavailable:$($_.Exception.Message)" | Add-Content $Report
}
"is_64_bit_os=$([Environment]::Is64BitOperatingSystem)" | Add-Content $Report
"is_64_bit_process=$([Environment]::Is64BitProcess)" | Add-Content $Report
"powershell_version=$($PSVersionTable.PSVersion)" | Add-Content $Report
Get-FileHash (Join-Path $Root "windows_process_probe.cr") -Algorithm SHA256 |
  ForEach-Object { "source_sha256=$($_.Hash)" } | Add-Content $Report
try {
  if (!(Test-Path -LiteralPath $Manifest -PathType Leaf)) { throw "Missing kit manifest: $Manifest" }
  $ManifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash
  "manifest_sha256=$ManifestHash" | Add-Content $Report
  $ManifestCount = 0
  foreach ($line in Get-Content -LiteralPath $Manifest) {
    if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw "Malformed manifest line: $line" }
    $Expected = $Matches[1]
    $Relative = $Matches[2]
    $Candidate = Join-Path $Root ($Relative -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (!(Test-Path -LiteralPath $Candidate -PathType Leaf)) { throw "Manifest file missing: $Relative" }
    $Actual = (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash
    if ($Actual -ne $Expected) { throw "Manifest hash mismatch: $Relative" }
    $ManifestCount++
  }
  if ($ManifestCount -eq 0) { throw "Kit manifest is empty" }
  "manifest_check=pass" | Add-Content $Report
  "manifest_entries=$ManifestCount" | Add-Content $Report
  Copy-Item -LiteralPath $Manifest -Destination (Join-Path $Run "kit-manifest.sha256")

  if (Test-Path -LiteralPath $BuildDir) {
    $buildItem = Get-Item -LiteralPath $BuildDir -Force
    if (($buildItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing redirected build directory: $BuildDir"
    }
    if (!$buildItem.PSIsContainer) { throw "Refusing non-directory build path: $BuildDir" }
    Remove-Item -LiteralPath $BuildDir -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

  $crystal = Get-Command crystal -ErrorAction Stop
  "crystal_path=$($crystal.Source)" | Add-Content $Report
  (& crystal --version 2>&1 | Out-String) | Add-Content $Report
  $DefaultCrystalPath = ((& crystal env CRYSTAL_PATH) | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) { throw "crystal env CRYSTAL_PATH failed" }
  $env:CRYSTAL_PATH = "$(Join-Path $Root 'workspace\process-supervision\src');$(Join-Path $Root 'workspace\process-handle\src');$DefaultCrystalPath"
  $Exe = Join-Path $BuildDir "windows_process_probe.exe"
  $BuildLog = Join-Path $Run "build.log"
  & crystal build --no-color (Join-Path $Root "windows_process_probe.cr") -o $Exe *>&1 |
    Out-File -FilePath $BuildLog -Encoding UTF8
  $BuildExit = $LASTEXITCODE
  "crystal_build_exit=$BuildExit" | Add-Content $Report
  if ($BuildExit -ne 0) { $ExitCode = 2; throw "Crystal build failed with code $BuildExit" }
  $env:PROCESS_PROBE_WORKDIR = $ChildDir
  $Result = Join-Path $Run "results.jsonl"
  $Stderr = Join-Path $Run "stderr.log"
  $StartArgs = @{
    FilePath = $Exe; WorkingDirectory = $Root; RedirectStandardOutput = $Result
    RedirectStandardError = $Stderr; PassThru = $true; NoNewWindow = $true
  }
  # Optional: run only the probe EXECUTABLE through a launcher. On an elevated CI runner,
  # PROCESS_PROBE_LAUNCHER=<job_explore.exe> runs the probe with a filtered (unelevated) token while the
  # build and this wrapper stay elevated. Unset = the probe starts normally.
  if ($env:PROCESS_PROBE_LAUNCHER) {
    $StartArgs.FilePath = $env:PROCESS_PROBE_LAUNCHER
    $StartArgs.ArgumentList = @('launch-unelevated', '--', $Exe)
    "probe_launcher=$($env:PROCESS_PROBE_LAUNCHER)" | Add-Content $Report
  }
  $p = Start-Process @StartArgs
  if ($p.WaitForExit(1800000)) {
    if ($p.ExitCode -ne 0) { $ExitCode = 1 }
    "run_state=exited`nexit_code=$($p.ExitCode)" | Set-Content -Encoding UTF8 (Join-Path $Run "run-status.txt")
  } else {
    try { $p.Kill() } catch {}
    try { $p.WaitForExit(5000) | Out-Null } catch {}
    $ExitCode = 124
    "run_state=timeout-1800s`nexit_code=124" | Set-Content -Encoding UTF8 (Join-Path $Run "run-status.txt")
  }
  try {
    $ValidCount = Assert-CompleteWindowsResults -CoveragePath (Join-Path $Root 'COVERAGE.md') -ResultsPath $Result
    "qualification_validation=pass cases=$ValidCount" | Set-Content -Encoding UTF8 (Join-Path $Run 'coverage-validation.log')
  } catch {
    "qualification_validation=fail error=$($_.Exception.Message)" | Set-Content -Encoding UTF8 (Join-Path $Run 'coverage-validation.log')
    if ($ExitCode -eq 0) { $ExitCode = 1 }
  }

  # Bind the handback to the same kit admitted before compilation. Rehash both
  # the manifest and every covered file so mid-run edits cannot silently qualify.
  try {
    $PostManifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash
    if ($PostManifestHash -ne $ManifestHash) { throw 'Manifest changed during native run' }
    $PostManifestCount = 0
    foreach ($line in Get-Content -LiteralPath $Manifest) {
      if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw "Malformed manifest line: $line" }
      $Expected = $Matches[1]
      $Relative = $Matches[2]
      $Candidate = Join-Path $Root ($Relative -replace '/', [IO.Path]::DirectorySeparatorChar)
      if (!(Test-Path -LiteralPath $Candidate -PathType Leaf)) { throw "Manifest file missing: $Relative" }
      $Actual = (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash
      if ($Actual -ne $Expected) { throw "Manifest hash mismatch: $Relative" }
      $PostManifestCount++
    }
    if ($PostManifestCount -ne $ManifestCount) { throw 'Manifest entry count changed during native run' }
    'post_manifest_check=pass' | Add-Content $Report
    "manifest_entries_post=$PostManifestCount" | Add-Content $Report
    'post_manifest_check=pass' | Set-Content -Encoding UTF8 (Join-Path $Run 'post-manifest-check.log')
  } catch {
    'post_manifest_check=fail' | Add-Content $Report
    "post_manifest_check=fail error=$($_.Exception.Message)" | Set-Content -Encoding UTF8 (Join-Path $Run 'post-manifest-check.log')
    if ($ExitCode -eq 0) { $ExitCode = 1 }
  }
} catch {
  if ($ExitCode -eq 0) { $ExitCode = 125 }
  "wrapper_error=$($_.Exception.GetType().FullName):$($_.Exception.Message)" |
    Add-Content $Report
  ($_.ScriptStackTrace | Out-String) | Set-Content -Encoding UTF8 (Join-Path $Run "wrapper-error.log")
} finally {
  $Handback = Join-Path $Root "windows-probe-handback.zip"
  if (Test-Path $Handback) { Remove-Item $Handback -Force }
  Compress-Archive -Path $Run -DestinationPath $Handback -Force
  Write-Host "Handback: $Handback"
}

exit $ExitCode
