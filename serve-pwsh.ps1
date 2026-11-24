<#
.SYNOPSIS
  Serve a PowerShell REPL on a local TCP port, for use behind `peer.py serve` (ham tunnel).

.DESCRIPTION
  Listens on 127.0.0.1:<Port> and, per connection, spawns PowerShell with stdin/stdout/stderr
  wired to the socket. The shell runs as a live REPL (no -Command/-File), so each line is
  executed as it arrives and its output streams straight back. This is line-mode: you get a
  prompt and command output, but not a full terminal (no arrow keys / ANSI editing) -- for that,
  use the Windows OpenSSH server instead.

  Pair with the tunnel:
      pwsh -NoProfile -File .\serve-pwsh.ps1          # this listener
      uv run peer.py serve --local-port 4444          # bridge it to the relay

.PARAMETER Shell
  Which shell to launch. 'pwsh.exe' (PowerShell 7, default) or 'powershell.exe' (Windows 5.1).
  Use a full path if it is not on PATH, e.g. 'C:\Program Files\PowerShell\7\pwsh.exe'.

.PARAMETER ShellArgs
  Arguments for the shell. Default keeps it a clean REPL. Do NOT add '-Command -' or '-File -':
  those wait for stdin EOF, which over the tunnel arrives as a full close, so no output returns.

.EXAMPLE
  pwsh -NoProfile -File .\serve-pwsh.ps1 -Shell powershell.exe -Port 4444
#>
param(
  [string]$BindAddress = '127.0.0.1',
  [int]   $Port        = 4444,
  [string]$Shell       = 'pwsh.exe',
  [string]$ShellArgs   = '-NoLogo -NoProfile'
)

$ErrorActionPreference = 'Stop'

# Resolve the shell up front so we fail with a clear message, not per-connection.
$resolved = (Get-Command $Shell -ErrorAction SilentlyContinue)?.Source
if (-not $resolved) {
  if ($Shell -eq 'pwsh.exe' -and (Test-Path 'C:\Program Files\PowerShell\7\pwsh.exe')) {
    $resolved = 'C:\Program Files\PowerShell\7\pwsh.exe'
  } else {
    throw "Shell '$Shell' not found on PATH. Pass -Shell with a full path, or 'powershell.exe'."
  }
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($BindAddress), $Port)
$listener.Start()
Write-Host "pwsh listener on ${BindAddress}:$Port -> $resolved  (Ctrl-C to stop)"

try {
  while ($true) {
    $client = $listener.AcceptTcpClient()     # one session at a time
    $client.NoDelay = $true
    $net = $client.GetStream()
    $out = [System.IO.Stream]::Synchronized($net)   # stdout + stderr may write at once

    $psi = [System.Diagnostics.ProcessStartInfo]::new($resolved, $ShellArgs)
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $t1 = $proc.StandardOutput.BaseStream.CopyToAsync($out)
    $t2 = $proc.StandardError.BaseStream.CopyToAsync($out)
    $t3 = $net.CopyToAsync($proc.StandardInput.BaseStream)

    try { $proc.WaitForExit() } catch {}
    foreach ($t in @($t1, $t2, $t3)) { try { [void]$t.Wait(500) } catch {} }
    try { $net.Dispose() } catch {}
    try { $client.Dispose() } catch {}
  }
}
finally {
  $listener.Stop()
}
