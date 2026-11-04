# How pwsh starts native programs, as JSON lines. Run elevated, and under the de-elevated token
# (job_explore launch-unelevated -- pwsh -File pwsh_native.ps1 -Probe <exe>), to compare.
#
# The first unelevated runs (41771599247) failed every captured native command with "Access is denied", followed by
# "StandardOutputEncoding is only supported when standard output is redirected" (PowerShell's retry clears the
# redirection but keeps the encoding, which hides the first error). Those runs predate the launcher's token
# owner / default-DACL fix (10a8f97), so this repeats the same launch shapes under the fixed token. Each case records
# the exception chain, so the first failure is visible; .NET's Process.Start is also called directly, which bypasses
# PowerShell's retry. Nothing here runs a native command to gather information about itself.
param([string]$Probe = "")

$ErrorActionPreference = "Continue"
$cmd = Join-Path $env:SystemRoot "System32\cmd.exe"

function Emit([string]$name, [hashtable]$fields) {
  $fields["probe"] = "pwsh_native"
  $fields["case"] = $name
  [Console]::Out.WriteLine(($fields | ConvertTo-Json -Compress -Depth 4))
  [Console]::Out.Flush()
}

function Describe($err) {
  $chain = @()
  $e = $err
  if ($e -is [System.Management.Automation.ErrorRecord]) { $e = $e.Exception }
  while ($e) {
    $item = @{ type = $e.GetType().FullName; message = $e.Message; hresult = ("0x{0:X8}" -f $e.HResult) }
    if ($e -is [System.ComponentModel.Win32Exception]) { $item["native_error"] = $e.NativeErrorCode }
    $chain += $item
    $e = $e.InnerException
  }
  return $chain
}

function Try-Case([string]$name, [scriptblock]$body) {
  $global:LASTEXITCODE = $null
  $t = [Diagnostics.Stopwatch]::StartNew()
  try {
    $r = & $body
    $f = @{ ok = $true; ms = [int]$t.ElapsedMilliseconds; last_exit_code = $global:LASTEXITCODE }
    if ($r -is [hashtable]) { foreach ($k in $r.Keys) { $f[$k] = $r[$k] } }
    elseif ($null -ne $r) { $s = ($r | Out-String).Trim(); $f["output"] = $s.Substring(0, [Math]::Min($s.Length, 200)) }
    Emit $name $f
  } catch {
    Emit $name @{ ok = $false; ms = [int]$t.ElapsedMilliseconds; last_exit_code = $global:LASTEXITCODE; errors = (Describe $_) }
  }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $id
Emit "pwsh_platform" @{
  ps_version = $PSVersionTable.PSVersion.ToString()
  framework = [Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
  user = $id.Name
  administrators_role_active = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  integrity_groups = @($id.Groups | ForEach-Object { $_.Value } | Where-Object { $_ -like "S-1-16-*" })
  session = [Diagnostics.Process]::GetCurrentProcess().SessionId
  native_command_error_action = "$PSNativeCommandUseErrorActionPreference"
}

Try-Case "native_uncaptured_cmd_exit_7" { & $cmd /c "exit 7"; @{ exit = $LASTEXITCODE } }
Try-Case "native_captured_cmd_ver" { $o = & $cmd /c ver 2>&1 | Out-String; @{ output = $o.Trim(); exit = $LASTEXITCODE } }
Try-Case "native_captured_whoami" { $o = & whoami 2>&1 | Out-String; @{ output = $o.Trim(); exit = $LASTEXITCODE } }
Try-Case "native_assigned_to_variable" { $o = & $cmd /c "echo hello"; @{ output = "$o"; exit = $LASTEXITCODE } }
if ($Probe) {
  Try-Case "native_uncaptured_probe_child" { & $Probe --child-sleep 10; @{ exit = $LASTEXITCODE } }
  Try-Case "native_captured_probe_child" { $o = & $Probe --child-sleep 10 2>&1 | Out-String; @{ exit = $LASTEXITCODE; output = $o.Trim() } }
}
Try-Case "dotnet_process_start_redirected" {
  $psi = [Diagnostics.ProcessStartInfo]::new($cmd, "/c ver")
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEnd()
  $p.WaitForExit()
  @{ exit = $p.ExitCode; output = $out.Trim() }
}
Try-Case "dotnet_process_start_redirected_stdin_too" {
  $psi = [Diagnostics.ProcessStartInfo]::new($cmd, "/c ver")
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [Diagnostics.Process]::Start($psi)
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEnd()
  $p.WaitForExit()
  @{ exit = $p.ExitCode; output = $out.Trim() }
}
Try-Case "dotnet_process_start_not_redirected" {
  $psi = [Diagnostics.ProcessStartInfo]::new($cmd, "/c exit 5")
  $psi.UseShellExecute = $false
  $p = [Diagnostics.Process]::Start($psi)
  $p.WaitForExit()
  @{ exit = $p.ExitCode }
}
Try-Case "dotnet_process_start_create_no_window" {
  $psi = [Diagnostics.ProcessStartInfo]::new($cmd, "/c exit 6")
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $p = [Diagnostics.Process]::Start($psi)
  $p.WaitForExit()
  @{ exit = $p.ExitCode }
}
Try-Case "start_process_nonewwindow" {
  $p = Start-Process -FilePath $cmd -ArgumentList "/c", "exit 4" -NoNewWindow -Wait -PassThru
  @{ exit = $p.ExitCode }
}
