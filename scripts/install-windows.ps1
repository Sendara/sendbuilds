$ErrorActionPreference = "Stop"

$BinName = "sendbuilds.exe"
$ShimName = "sendbuilds.cmd"
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

$ShimPath = Join-Path $DestDir $ShimName
"@echo off`r`n`"%~dp0sendbuilds.exe`" %*" | Out-File -Encoding ascii -NoNewline $ShimPath

Write-Host "Installed: $DestBin"
Write-Host "Installed: $ShimPath"

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$NormDest = $DestDir.TrimEnd('\').ToLowerInvariant()
$PathEntries = @()
if (-not [string]::IsNullOrWhiteSpace($UserPath)) {
  $PathEntries = $UserPath -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
$HasDest = $PathEntries | Where-Object { $_.TrimEnd('\').ToLowerInvariant() -eq $NormDest }
if (-not $HasDest) {
  $NewPath = if ([string]::IsNullOrWhiteSpace($UserPath)) { $DestDir } else { "$UserPath;$DestDir" }
  [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
  Write-Host "Added '$DestDir' to User PATH. Restart terminal to use 'sendbuilds'."
} else {
  Write-Host "User PATH already includes '$DestDir'."
}

# Also update PATH for the current PowerShell session immediately.
$ProcessEntries = $env:Path -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$HasDestInProcess = $ProcessEntries | Where-Object { $_.TrimEnd('\').ToLowerInvariant() -eq $NormDest }
if (-not $HasDestInProcess) {
  $env:Path = "$DestDir;$env:Path"
}

Write-Host ""
if (Get-Command sendbuilds -ErrorAction SilentlyContinue) {
  Write-Host "Verified: 'sendbuilds' is available in this terminal."
  Write-Host "Run:"
  Write-Host "  sendbuilds --help"
} else {
  Write-Host "Could not resolve 'sendbuilds' in this terminal yet."
  Write-Host "Try full path now:"
  Write-Host "  `"$DestBin`" --help"
  Write-Host "Then open a NEW terminal and run:"
  Write-Host "  sendbuilds --help"
}
Write-Host ""
