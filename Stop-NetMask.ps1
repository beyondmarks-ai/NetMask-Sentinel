param([switch]$ValidateOnly)

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
$PidFile = Join-Path $ProjectDir "runtime\netmask.pid"
if (-not (Test-Path -LiteralPath $PidFile)) {
    Write-Host "NetMask Sentinel is not recorded as running."
    exit 0
}
$serverPid = [int](Get-Content -Raw -LiteralPath $PidFile)
$process = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
if (-not $process) {
    Remove-Item -LiteralPath $PidFile -Force
    Write-Host "NetMask Sentinel was already stopped."
    exit 0
}
$listener = netstat -ano | Select-String -Pattern "LISTENING\s+$serverPid\s*$"
if ($process.ProcessName -notlike "python*" -or -not $listener) {
    throw "PID $serverPid is not the Python process listening on NetMask port 5000; it was not stopped."
}
if ($ValidateOnly) {
    Write-Host "Stop target validation passed for PID $serverPid."
    exit 0
}
Stop-Process -Id $serverPid
Remove-Item -LiteralPath $PidFile -Force
Write-Host "NetMask Sentinel stopped."