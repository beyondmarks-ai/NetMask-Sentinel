param(
    [string]$Destination = "github-release\NetMask-Sentinel"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ExportRoot = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot $Destination))
$AllowedRoot = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot "github-release"))

if (-not $ExportRoot.StartsWith($AllowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Destination must remain under $AllowedRoot"
}
if ($ExportRoot -eq $AllowedRoot) {
    throw "Destination must be a child directory, not the export root itself."
}

if (Test-Path -LiteralPath $ExportRoot) {
    Remove-Item -LiteralPath $ExportRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ExportRoot | Out-Null

Set-Location -LiteralPath $ProjectRoot
$Files = git ls-files --cached --others --exclude-standard
if ($LASTEXITCODE -ne 0) {
    throw "Unable to enumerate repository files."
}
$Excluded = @("input_logs.csv", "output_logs.csv", "output_logs_.csv")
foreach ($RelativePath in $Files) {
    $Normalized = $RelativePath.Replace("/", "\")
    if ($Normalized -in $Excluded) { continue }
    $Source = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot $Normalized))
    if (-not $Source.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to export a path outside the repository: $Source"
    }
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { continue }
    $Target = Join-Path $ExportRoot $Normalized
    $TargetParent = Split-Path -Parent $Target
    New-Item -ItemType Directory -Force -Path $TargetParent | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Target
}

Set-Location -LiteralPath $ExportRoot
git init -b main | Out-Null
git config user.name "NetMask Sentinel"
git config user.email "netmask-sentinel@users.noreply.github.com"
git add --all
git -c commit.gpgsign=false commit -m "Initial public release" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Unable to create the clean initial commit."
}

Write-Host "Clean repository created: $ExportRoot"
Write-Host "Commit: $(git rev-parse --short HEAD)"
Write-Host "Remote: $(if (git remote) { git remote -v } else { 'none' })"