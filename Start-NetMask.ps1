param(
    [switch]$NoBrowser,
    [switch]$ValidateOnly
)
$ErrorActionPreference = "Stop"

$ProjectDir = $PSScriptRoot
$RuntimeDir = Join-Path $ProjectDir "runtime"
$PythonExe = Join-Path $ProjectDir ".venv\Scripts\python.exe"
$Requirements = Join-Path $ProjectDir "requirements.txt"
$RequirementsMarker = Join-Path $ProjectDir ".venv\netmask-requirements.sha256"
$StdoutLog = Join-Path $RuntimeDir "server.stdout.log"
$StderrLog = Join-Path $RuntimeDir "server.stderr.log"
$PidFile = Join-Path $RuntimeDir "netmask.pid"
$HealthUrl = "http://127.0.0.1:5000/health/ready"
$DashboardUrl = "http://127.0.0.1:5000/guest"

Set-Location -LiteralPath $ProjectDir
Remove-Item Env:PYTHONHOME, Env:PYTHONPATH -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

function Test-NetMaskReady {
    try {
        $response = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 2
        return $response.status -in @("ready", "degraded")
    }
    catch {
        return $false
    }
}

function Save-NetMaskListenerPid {
    $listenerLine = netstat -ano |
        Select-String -Pattern '^\s*TCP\s+\S+:5000\s+\S+\s+LISTENING\s+\d+\s*$' |
        Select-Object -First 1
    if ($listenerLine -and $listenerLine.Line -match '(\d+)\s*$') {
        Set-Content -LiteralPath $PidFile -Value $Matches[1] -NoNewline
    }
}

if (Test-NetMaskReady) {
    Save-NetMaskListenerPid
    if (-not $NoBrowser) { Start-Process $DashboardUrl }
    exit 0
}

if (-not (Test-Path -LiteralPath $PythonExe)) {
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        & $pyLauncher.Source -3.11 -m venv (Join-Path $ProjectDir ".venv")
    }
    elseif ($pythonCommand) {
        & $pythonCommand.Source -m venv (Join-Path $ProjectDir ".venv")
    }
    else {
        throw "Python 3.10-3.12 is required. Install Python, then double-click the shortcut again."
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $PythonExe)) {
        throw "The Python virtual environment could not be created."
    }
}

$requirementsHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Requirements).Hash
$installedHash = if (Test-Path -LiteralPath $RequirementsMarker) {
    (Get-Content -Raw -LiteralPath $RequirementsMarker).Trim()
} else {
    ""
}
if ($requirementsHash -ne $installedHash) {
    Write-Host "Preparing NetMask Sentinel dependencies. This is only needed after setup or an update..."
    & $PythonExe -m pip install -r $Requirements
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed. Check the internet connection and runtime\server.stderr.log."
    }
    Set-Content -LiteralPath $RequirementsMarker -Value $requirementsHash -NoNewline
}

$npcap = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if (-not $npcap) {
    throw "Npcap is required for packet capture. Install Npcap with WinPcap API compatibility enabled."
}
if ($npcap.Status -ne "Running") {
    try {
        Start-Service -Name "npcap"
    }
    catch {
        throw "Npcap is installed but not running. Start this shortcut as Administrator once."
    }
}

if ($ValidateOnly) {
    Write-Host "NetMask Sentinel launcher validation passed."
    exit 0
}

$env:NETMASK_ENV = "development"
$env:NETMASK_HOST = "0.0.0.0"
$env:NETMASK_PORT = "5000"
$env:FLASK_DEBUG = "false"
$env:CAPTURE_ENABLED = "true"
$env:MPLCONFIGDIR = Join-Path $ProjectDir ".matplotlib-cache"

Remove-Item -LiteralPath $StdoutLog, $StderrLog -Force -ErrorAction SilentlyContinue
$server = Start-Process `
    -FilePath $PythonExe `
    -ArgumentList "application.py" `
    -WorkingDirectory $ProjectDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -PassThru

Set-Content -LiteralPath $PidFile -Value $server.Id -NoNewline

for ($attempt = 0; $attempt -lt 90; $attempt++) {
    if ($server.HasExited) {
        $details = if (Test-Path -LiteralPath $StderrLog) {
            Get-Content -Raw -LiteralPath $StderrLog
        } else {
            "No server error log was produced."
        }
        throw "NetMask Sentinel stopped during startup.`n$details"
    }
    function Save-NetMaskListenerPid {
    $listenerLine = netstat -ano |
        Select-String -Pattern '^\s*TCP\s+\S+:5000\s+\S+\s+LISTENING\s+\d+\s*$' |
        Select-Object -First 1
    if ($listenerLine -and $listenerLine.Line -match '(\d+)\s*$') {
        Set-Content -LiteralPath $PidFile -Value $Matches[1] -NoNewline
    }
}

if (Test-NetMaskReady) {
        if (-not $NoBrowser) { Start-Process $DashboardUrl }
        exit 0
    }
    Start-Sleep -Milliseconds 500
}

throw "NetMask Sentinel did not become ready. Review runtime\server.stderr.log."