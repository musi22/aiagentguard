param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment,
    [Parameter(Mandatory = $true)]
    [string]$ImageTag
)

$ErrorActionPreference = "Stop"
if ($Environment -eq "prod" -and $ImageTag -eq "latest") {
    throw "Production cannot use the mutable 'latest' tag."
}

$tfDir = "infra/terraform/environments/$Environment"
$backendConfig = if ($env:BACKEND_CONFIG) { $env:BACKEND_CONFIG } else { "backend.hcl" }
$tfvarsFile = if ($env:TF_VARS_FILE) { $env:TF_VARS_FILE } else { "terraform.tfvars" }
terraform "-chdir=$tfDir" init "-backend-config=$backendConfig"

$tfvarsPath = Join-Path $tfDir $tfvarsFile
if (Test-Path -LiteralPath $tfvarsPath) {
    terraform "-chdir=$tfDir" apply -auto-approve "-var-file=$tfvarsFile" "-var=image_tag=$ImageTag" "-target=module.agentguard.azurerm_container_registry.main"
} else {
    terraform "-chdir=$tfDir" apply -auto-approve "-var=image_tag=$ImageTag" "-target=module.agentguard.azurerm_container_registry.main"
}

$registry = az acr list --resource-group "rg-agentguard-$Environment" --query "[0].name" -o tsv
foreach ($service in @("api", "gateway", "worker")) {
    az acr build --registry $registry --image "agentguard-${service}:$ImageTag" --target $service .
}

if (Test-Path -LiteralPath $tfvarsPath) {
    terraform "-chdir=$tfDir" plan "-var-file=$tfvarsFile" "-var=image_tag=$ImageTag" "-target=module.agentguard.azurerm_container_app_job.migration" "-out=migration.tfplan"
} else {
    terraform "-chdir=$tfDir" plan "-var=image_tag=$ImageTag" "-target=module.agentguard.azurerm_container_app_job.migration" "-out=migration.tfplan"
}
terraform "-chdir=$tfDir" apply migration.tfplan

$resourceGroup = terraform "-chdir=$tfDir" output -raw resource_group_name
$migrationJob = terraform "-chdir=$tfDir" output -raw migration_job_name
$execution = az containerapp job start --resource-group $resourceGroup --name $migrationJob --query name -o tsv

do {
    Start-Sleep -Seconds 10
    $status = az containerapp job execution show --resource-group $resourceGroup --name $migrationJob --job-execution-name $execution --query properties.status -o tsv
    if ($status -in @("Failed", "Stopped", "Degraded")) {
        throw "Migration execution $execution failed with status $status"
    }
} until ($status -eq "Succeeded")

if (Test-Path -LiteralPath $tfvarsPath) {
    terraform "-chdir=$tfDir" plan "-var-file=$tfvarsFile" "-var=image_tag=$ImageTag" "-out=tfplan"
} else {
    terraform "-chdir=$tfDir" plan "-var=image_tag=$ImageTag" "-out=tfplan"
}
terraform "-chdir=$tfDir" apply tfplan

if ($Environment -eq "prod") {
    $containerEnvironment = terraform "-chdir=$tfDir" output -raw container_app_environment_name
    $connectionIds = az network private-endpoint-connection list --resource-group $resourceGroup --name $containerEnvironment --type Microsoft.App/managedEnvironments --query "[?properties.privateLinkServiceConnectionState.status=='Pending'].id" -o tsv
    foreach ($connectionId in $connectionIds) {
        if ($connectionId) {
            az network private-endpoint-connection approve --id $connectionId --description "Approved by AgentGuard deployment" | Out-Null
        }
    }
}

$staticWebApp = terraform "-chdir=$tfDir" output -raw static_web_app_name
$apiUrl = terraform "-chdir=$tfDir" output -raw api_url
$gatewayUrl = terraform "-chdir=$tfDir" output -raw gateway_url
Push-Location apps/web
$env:NEXT_PUBLIC_API_URL = $apiUrl
$env:NEXT_PUBLIC_GATEWAY_URL = $gatewayUrl
npm install
npm run build
Pop-Location
$deploymentToken = az staticwebapp secrets list --resource-group $resourceGroup --name $staticWebApp --query properties.apiKey -o tsv
npx --yes @azure/static-web-apps-cli deploy apps/web/out --deployment-token $deploymentToken --env production

Write-Host "AgentGuard $Environment deployed with image tag $ImageTag; migrations succeeded first."
