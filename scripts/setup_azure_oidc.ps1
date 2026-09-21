param(
    [string]$SubscriptionId,
    [string]$Location = "centralindia",
    [string]$GitHubRepo = "musi22/aiagentguard",
    [string]$ResourceGroupName = "rg-agentguard-tfstate-dev"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Step 1: Checking Azure CLI Authentication ===" -ForegroundColor Cyan
if (-not (Get-Command "az" -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI ('az') is not installed. Run in Azure Cloud Shell (https://shell.azure.com) or install Azure CLI."
    exit 1
}

$accountRaw = az account show -o json 2>$null
if (-not $accountRaw) {
    Write-Host "Logging into Azure..."
    az login
    $accountRaw = az account show -o json
}

$account = $accountRaw | ConvertFrom-Json
$tenantId = $account.tenantId
if (-not $SubscriptionId) {
    $SubscriptionId = $account.id
}

Write-Host "Using Subscription ID: $SubscriptionId"
Write-Host "Using Tenant ID:       $tenantId"
Write-Host "Using Location:        $Location"
Write-Host "Target GitHub Repo:    $GitHubRepo"

az account set --subscription $SubscriptionId

Write-Host "=== Step 2: Creating Terraform State Storage Account ===" -ForegroundColor Cyan
az group create --name $ResourceGroupName --location $Location -o none

$rand = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
$storageAccount = "stagtfs$rand"

Write-Host "Creating storage account: $storageAccount ..."
az storage account create `
    --name $storageAccount `
    --resource-group $ResourceGroupName `
    --location $Location `
    --sku Standard_LRS `
    --min-tls-version TLS1_2 `
    --allow-blob-public-access false `
    --output none

az storage container create `
    --account-name $storageAccount `
    --name "tfstate" `
    --auth-mode login `
    --output none

Write-Host "=== Step 3: Configuring Microsoft Entra App & Service Principal ===" -ForegroundColor Cyan
$appName = "agentguard-github-actions"
$appId = az ad app list --display-name $appName --query "[0].appId" -o tsv
if (-not $appId) {
    Write-Host "Creating Entra App Registration: $appName ..."
    $appId = az ad app create --display-name $appName --query appId -o tsv
}
Write-Host "App ID (Client ID): $appId"

$spId = az ad sp list --filter "appId eq '$appId'" --query "[0].id" -o tsv
if (-not $spId) {
    Write-Host "Creating Service Principal..."
    $spId = az ad sp create --id $appId --query id -o tsv
}

Write-Host "=== Step 4: Configuring GitHub Actions OIDC Federated Credentials ===" -ForegroundColor Cyan
# For dev environment
$devParams = @{
    name = "github-env-dev"
    issuer = "https://token.actions.githubusercontent.com"
    subject = "repo:$GitHubRepo:environment:dev"
    description = "GitHub Actions OIDC for AgentGuard dev environment"
    audiences = @("api://AzureADTokenExchange")
} | ConvertTo-Json -Compress

az ad app federated-credential create --id $appId --parameters $devParams 2>$null

# For main branch
$mainParams = @{
    name = "github-branch-main"
    issuer = "https://token.actions.githubusercontent.com"
    subject = "repo:$GitHubRepo:ref:refs/heads/main"
    description = "GitHub Actions OIDC for AgentGuard main branch"
    audiences = @("api://AzureADTokenExchange")
} | ConvertTo-Json -Compress

az ad app federated-credential create --id $appId --parameters $mainParams 2>$null

Write-Host "=== Step 5: Assigning RBAC Permissions ===" -ForegroundColor Cyan
az role assignment create --assignee $appId --role "Contributor" --scope "/subscriptions/$SubscriptionId" -o none 2>$null
az role assignment create --assignee $appId --role "User Access Administrator" --scope "/subscriptions/$SubscriptionId" -o none 2>$null

$storageId = az storage account show --name $storageAccount --resource-group $ResourceGroupName --query id -o tsv
az role assignment create --assignee $appId --role "Storage Blob Data Owner" --scope $storageId -o none 2>$null

Write-Host "=== Step 6: Setting GitHub Actions Variables ===" -ForegroundColor Cyan
if (Get-Command "gh" -ErrorAction SilentlyContinue) {
    gh variable set AZURE_CLIENT_ID --body "$appId" --repo "$GitHubRepo"
    gh variable set AZURE_TENANT_ID --body "$tenantId" --repo "$GitHubRepo"
    gh variable set AZURE_SUBSCRIPTION_ID --body "$SubscriptionId" --repo "$GitHubRepo"
    gh variable set TF_STATE_RESOURCE_GROUP --body "$ResourceGroupName" --repo "$GitHubRepo"
    gh variable set TF_STATE_STORAGE_ACCOUNT --body "$storageAccount" --repo "$GitHubRepo"
    Write-Host "✓ All GitHub variables successfully configured!" -ForegroundColor Green
} else {
    Write-Host "Variables to configure on GitHub ($GitHubRepo -> Settings -> Secrets and variables -> Actions -> Variables):" -ForegroundColor Yellow
    Write-Host "  AZURE_CLIENT_ID:          $appId"
    Write-Host "  AZURE_TENANT_ID:          $tenantId"
    Write-Host "  AZURE_SUBSCRIPTION_ID:    $SubscriptionId"
    Write-Host "  TF_STATE_RESOURCE_GROUP:  $ResourceGroupName"
    Write-Host "  TF_STATE_STORAGE_ACCOUNT: $storageAccount"
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "✓ Azure OIDC & Terraform Remote State setup completed successfully!" -ForegroundColor Green
Write-Host "Deploy workflow can now be triggered with:" -ForegroundColor Green
Write-Host "  gh workflow run `"Deploy dev`" --repo $GitHubRepo" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Green
