param(
    [string]$Location = "centralindia",
    [string]$NamePrefix = "netmask-sentinel"
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw "Azure CLI is required." }
$account = az account show --query id -o tsv
if ($LASTEXITCODE -ne 0 -or -not $account) { throw "Run 'az login' and select a subscription first." }

$suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$resourceGroup = "rg-$NamePrefix-$suffix"
$storageAccount = ("nms" + $suffix).ToLower()
$registry = ("nmsacr" + $suffix).ToLower()
$environment = "cae-$NamePrefix-$suffix"
$appName = "ca-$NamePrefix-$suffix"
$imageTag = "${registry}.azurecr.io/netmask-sentinel:1"

function New-RandomSecret {
    $bytes = New-Object byte[] 48
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

$flaskSecret = New-RandomSecret
$sensorToken = New-RandomSecret

az group create --name $resourceGroup --location $Location --output none
az storage account create --name $storageAccount --resource-group $resourceGroup --location $Location --sku Standard_LRS --kind StorageV2 --allow-blob-public-access false --output none
$storageConnection = az storage account show-connection-string --name $storageAccount --resource-group $resourceGroup --query connectionString -o tsv
az acr create --name $registry --resource-group $resourceGroup --location $Location --sku Basic --admin-enabled true --output none
az acr build --registry $registry --image "netmask-sentinel:1" --no-logs .
if ($LASTEXITCODE -ne 0) { throw "Azure container build failed." }
$registryUser = az acr credential show --name $registry --query username -o tsv
$registryPassword = az acr credential show --name $registry --query "passwords[0].value" -o tsv
az containerapp env create --name $environment --resource-group $resourceGroup --location $Location --output none
az containerapp create `
    --name $appName `
    --resource-group $resourceGroup `
    --environment $environment `
    --image $imageTag `
    --ingress external `
    --target-port 5000 `
    --transport auto `
    --registry-server "${registry}.azurecr.io" `
    --registry-username $registryUser `
    --registry-password $registryPassword `
    --secrets "storage-connection=$storageConnection" "flask-secret=$flaskSecret" "sensor-token=$sensorToken" `
    --env-vars "NETMASK_ENV=production" "CAPTURE_ENABLED=false" "ENABLE_GUEST_ACCESS=false" "ENABLE_DEBUG_ROUTES=false" "AZURE_STORAGE_CONNECTION_STRING=secretref:storage-connection" "FLASK_SECRET_KEY=secretref:flask-secret" "NETMASK_SENSOR_INGEST_TOKEN=secretref:sensor-token" `
    --min-replicas 1 `
    --max-replicas 1 `
    --cpu 1.0 `
    --memory 2.0Gi `
    --output none
if ($LASTEXITCODE -ne 0) { throw "Azure Container App deployment failed." }

$fqdn = az containerapp show --name $appName --resource-group $resourceGroup --query properties.configuration.ingress.fqdn -o tsv
$cloudUrl = "https://$fqdn"
az containerapp update `
    --name $appName `
    --resource-group $resourceGroup `
    --set-env-vars "CORS_ORIGINS=$cloudUrl" `
    --output none
if ($LASTEXITCODE -ne 0) { throw "Could not configure the hosted dashboard origin." }
$runtimeDir = Join-Path $PSScriptRoot "runtime"
New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
@{
    resource_group = $resourceGroup
    app_name = $appName
    storage_account = $storageAccount
    registry = $registry
    cloud_url = $cloudUrl
    sensor_token = $sensorToken
    sensor_id = $env:COMPUTERNAME
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runtimeDir "azure-deployment.json")
& (Join-Path $PSScriptRoot "Configure-AzureSensor.ps1") -CloudUrl $cloudUrl -SensorToken $sensorToken
Write-Host "Hosted dashboard: $cloudUrl"
Write-Host "Deployment metadata and the sensor secret were saved under runtime (excluded from Git)."
