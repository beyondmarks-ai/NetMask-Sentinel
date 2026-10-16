param(
    [Parameter(Mandatory = $true)][string]$CloudUrl,
    [Parameter(Mandatory = $true)][string]$SensorToken,
    [string]$SensorId = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"
$uri = [Uri]$CloudUrl
if ($uri.Scheme -ne "https") { throw "The hosted dashboard URL must use HTTPS." }
if ($SensorToken.Length -lt 32) { throw "The sensor token must contain at least 32 characters." }
$runtimeDir = Join-Path $PSScriptRoot "runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
$configPath = Join-Path $runtimeDir "cloud-sensor.json"
@{
    cloud_url = $CloudUrl.TrimEnd('/')
    sensor_token = $SensorToken
    sensor_id = $SensorId
} | ConvertTo-Json | Set-Content -LiteralPath $configPath
Write-Host "Azure reporting configured for sensor '$SensorId'. Restart NetMask Sentinel to apply it."
