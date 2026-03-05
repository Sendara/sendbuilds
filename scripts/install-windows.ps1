$ErrorActionPreference = "Stop"

$BinName = "sendbuilds.exe"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceBin = Join-Path $ScriptDir $BinName

if (-not (Test-Path $SourceBin)) {
  throw "sendbuilds.exe not found next to install-windows.ps1"
}

$DefaultDest = Join-Path $HOME "bin"
$DestDir = if ($args.Count -gt 0 -and $args[0]) { $args[0] } else { $DefaultDest }
$DestBin = Join-Path $DestDir $BinName

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
Copy-Item -Force $SourceBin $DestBin

Write-Host "Installed: $DestBin"

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($UserPath -split ";" | Where-Object { $_ -eq $DestDir })) {
  $NewPath = if ([string]::IsNullOrWhiteSpace($UserPath)) { $DestDir } else { "$UserPath;$DestDir" }
  [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
  Write-Host "Added '$DestDir' to User PATH. Restart terminal to use 'sendbuilds'."
} else {
  Write-Host "User PATH already includes '$DestDir'."
}
