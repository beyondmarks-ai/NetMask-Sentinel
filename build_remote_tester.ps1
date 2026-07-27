param(
    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$BuildRoot = Join-Path $ProjectRoot "build\remote-tester"
$DistRoot = Join-Path $ProjectRoot "dist"
$TesterFolder = Join-Path $DistRoot "NetMask-Lab-Test"
$Archive = Join-Path $DistRoot "NetMask-Remote-Lab-Test.zip"

function Reset-SafeDirectory([string]$Path) {
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside the repository: $resolved"
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $resolved | Out-Null
}

Set-Location -LiteralPath $ProjectRoot
Reset-SafeDirectory $BuildRoot
Reset-SafeDirectory $DistRoot

& $PythonExecutable -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    --console `
    --name "NetMask-Lab-Test" `
    --distpath $DistRoot `
    --workpath $BuildRoot `
    --specpath $BuildRoot `
    (Join-Path $ProjectRoot "netmask_lab_traffic.py")
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

$Executable = Join-Path $TesterFolder "NetMask-Lab-Test.exe"
if (-not (Test-Path -LiteralPath $Executable)) {
    throw "Expected executable was not generated: $Executable"
}

$ExecutableHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Executable).Hash
$SourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath "netmask_lab_traffic.py").Hash
$Checksums = Join-Path $DistRoot "SHA256SUMS.txt"
$ChecksumContent = @(
    "NetMask-Lab-Test\NetMask-Lab-Test.exe  $ExecutableHash"
    "netmask_lab_traffic.py  $SourceHash"
) -join "`r`n"
Set-Content -LiteralPath $Checksums -Value $ChecksumContent -NoNewline

Copy-Item -LiteralPath "netmask_lab_traffic.py" -Destination $DistRoot
Copy-Item -LiteralPath "Run Remote Lab Test.cmd" -Destination $DistRoot
Copy-Item -LiteralPath "REMOTE-LAB-README.txt" -Destination $DistRoot

Compress-Archive -LiteralPath `
    $TesterFolder, `
    (Join-Path $DistRoot "netmask_lab_traffic.py"), `
    (Join-Path $DistRoot "Run Remote Lab Test.cmd"), `
    (Join-Path $DistRoot "REMOTE-LAB-README.txt"), `
    $Checksums `
    -DestinationPath $Archive `
    -CompressionLevel Optimal

Write-Host "Built $Archive"
Write-Host "SHA256 $((Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash)"