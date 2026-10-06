$ErrorActionPreference = "Stop"
$tokenPath = Join-Path $PSScriptRoot "runtime\lab-alert.token"
if (-not (Test-Path -LiteralPath $tokenPath)) {
    throw "No lab token exists yet. Start NetMask Sentinel once, then run this command again."
}
Get-Content -Raw -LiteralPath $tokenPath
