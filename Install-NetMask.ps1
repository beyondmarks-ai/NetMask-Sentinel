param([switch]$InstallNpcap)

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
Set-Location -LiteralPath $ProjectDir

function Get-Python311 {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        & $launcher.Source -3.11 -c "import sys" 2>$null
        if ($LASTEXITCODE -eq 0) { return @($launcher.Source, "-3.11") }
    }
    return $null
}

$python = Get-Python311
if (-not $python) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { throw "Python 3.11 is required and winget is unavailable. Install Python 3.11, then run this script again." }
    Write-Host "Installing Python 3.11..."
    & $winget.Source install --id Python.Python.3.11 --exact --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11 installation failed." }
    $python = Get-Python311
    if (-not $python) { throw "Python 3.11 was installed but is not available yet. Open a new PowerShell window and rerun this script." }
}

if (-not (Get-Service -Name npcap -ErrorAction SilentlyContinue)) {
    if (-not $InstallNpcap) {
        throw "Npcap is required for live capture. Rerun this script in an Administrator PowerShell with -InstallNpcap to install it."
    }
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { throw "Npcap must be installed manually because winget is unavailable." }
    Write-Host "Installing Npcap (accept the UAC prompt and enable WinPcap API-compatible mode if prompted)..."
    & $winget.Source install --id Insecure.Npcap --exact --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { throw "Npcap installation failed." }
}

$venvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) {
    & $python[0] $python[1] -m venv (Join-Path $ProjectDir ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Could not create the NetMask Python environment." }
}
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r (Join-Path $ProjectDir "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
& (Join-Path $ProjectDir "Start-NetMask.ps1") -NoBrowser
Write-Host "NetMask Sentinel is ready at http://127.0.0.1:5000/guest"
