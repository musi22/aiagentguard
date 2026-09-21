#!/usr/bin/env bash
set -euo pipefail

# AgentGuard: Automated Azure OIDC & Terraform State Setup
# This script sets up:
# 1. Resource group & Storage account for Terraform state with TLS 1.2 and blob container
# 2. Microsoft Entra App Registration & Service Principal for GitHub Actions
# 3. Federated Identity Credentials (OIDC) for GitHub Actions (environment: dev and branch: main)
# 4. RBAC roles (Contributor, User Access Administrator, Storage Blob Data Owner)
# 5. Automatically configures GitHub repository variables via `gh variable set`

GITHUB_REPO="${GITHUB_REPO:-musi22/aiagentguard}"
LOCATION="${LOCATION:-centralindia}"
TF_STATE_RG="${TF_STATE_RG:-rg-agentguard-tfstate-dev}"
CONTAINER_NAME="tfstate"
APP_NAME="agentguard-github-actions"

echo "=== Step 1: Checking Azure CLI Authentication ==="
if ! command -v az &> /dev/null; then
    echo "Error: Azure CLI ('az') is not installed or not in PATH."
    echo "Please run this script inside Azure Cloud Shell (https://shell.azure.com) or install Azure CLI."
    exit 1
fi

ACCOUNT_JSON="$(az account show -o json 2>/dev/null || true)"
if [ -z "$ACCOUNT_JSON" ]; then
    echo "Please log in to Azure:"
    az login
    ACCOUNT_JSON="$(az account show -o json)"
fi

SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-$(echo "$ACCOUNT_JSON" | jq -r '.id')}"
TENANT_ID="$(echo "$ACCOUNT_JSON" | jq -r '.tenantId')"

echo "Using Subscription ID: $SUBSCRIPTION_ID"
echo "Using Tenant ID:       $TENANT_ID"
echo "Using Location:        $LOCATION"
echo "Target GitHub Repo:    $GITHUB_REPO"

az account set --subscription "$SUBSCRIPTION_ID"

echo "=== Step 2: Creating Terraform State Storage Account ==="
az group create --name "$TF_STATE_RG" --location "$LOCATION" -o none

# Storage account names must be 3-24 lowercase letters/numbers
UNIQUE_SUFFIX="$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 6)"
TF_STATE_STORAGE_ACCOUNT="stagtfs${UNIQUE_SUFFIX}"

echo "Creating storage account: $TF_STATE_STORAGE_ACCOUNT ..."
az storage account create \
    --name "$TF_STATE_STORAGE_ACCOUNT" \
    --resource-group "$TF_STATE_RG" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --min-tls-version TLS1_2 \
    --allow-blob-public-access false \
    --output none

echo "Creating blob container: $CONTAINER_NAME ..."
az storage container create \
    --account-name "$TF_STATE_STORAGE_ACCOUNT" \
    --name "$CONTAINER_NAME" \
    --auth-mode login \
    --output none

echo "=== Step 3: Configuring Microsoft Entra App & Service Principal ==="
APP_ID="$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)"
if [ -z "$APP_ID" ]; then
    echo "Creating Entra App Registration: $APP_NAME ..."
    APP_ID="$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)"
fi
echo "App ID (Client ID): $APP_ID"

SP_ID="$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv)"
if [ -z "$SP_ID" ]; then
    echo "Creating Service Principal..."
    SP_ID="$(az ad sp create --id "$APP_ID" --query id -o tsv)"
fi
echo "Service Principal Object ID: $SP_ID"

echo "=== Step 4: Configuring GitHub Actions OIDC Federated Credentials ==="
# 1. For environment: dev
az ad app federated-credential create \
    --id "$APP_ID" \
    --parameters "{
        \"name\": \"github-env-dev\",
        \"issuer\": \"https://token.actions.githubusercontent.com\",
        \"subject\": \"repo:${GITHUB_REPO}:environment:dev\",
        \"description\": \"GitHub Actions OIDC for AgentGuard dev environment\",
        \"audiences\": [\"api://AzureADTokenExchange\"]
    }" 2>/dev/null || echo "Federated credential for dev environment already configured."

# 2. For branch: main
az ad app federated-credential create \
    --id "$APP_ID" \
    --parameters "{
        \"name\": \"github-branch-main\",
        \"issuer\": \"https://token.actions.githubusercontent.com\",
        \"subject\": \"repo:${GITHUB_REPO}:ref:refs/heads/main\",
        \"description\": \"GitHub Actions OIDC for AgentGuard main branch\",
        \"audiences\": [\"api://AzureADTokenExchange\"]
    }" 2>/dev/null || echo "Federated credential for main branch already configured."

echo "=== Step 5: Assigning RBAC Permissions ==="
# Contributor on the subscription
az role assignment create \
    --assignee "$APP_ID" \
    --role "Contributor" \
    --scope "/subscriptions/$SUBSCRIPTION_ID" \
    --output none 2>/dev/null || true

# User Access Administrator or Role Based Access Control Administrator on the subscription (for managed identity role assignments)
az role assignment create \
    --assignee "$APP_ID" \
    --role "User Access Administrator" \
    --scope "/subscriptions/$SUBSCRIPTION_ID" \
    --output none 2>/dev/null || true

# Storage Blob Data Owner on the Terraform state storage account
STORAGE_ID="$(az storage account show --name "$TF_STATE_STORAGE_ACCOUNT" --resource-group "$TF_STATE_RG" --query id -o tsv)"
az role assignment create \
    --assignee "$APP_ID" \
    --role "Storage Blob Data Owner" \
    --scope "$STORAGE_ID" \
    --output none 2>/dev/null || true

echo "=== Step 6: Setting GitHub Actions Variables ==="
if command -v gh &> /dev/null && gh auth status &> /dev/null; then
    echo "Configuring GitHub Repository Variables via gh CLI..."
    gh variable set AZURE_CLIENT_ID --body "$APP_ID" --repo "$GITHUB_REPO"
    gh variable set AZURE_TENANT_ID --body "$TENANT_ID" --repo "$GITHUB_REPO"
    gh variable set AZURE_SUBSCRIPTION_ID --body "$SUBSCRIPTION_ID" --repo "$GITHUB_REPO"
    gh variable set TF_STATE_RESOURCE_GROUP --body "$TF_STATE_RG" --repo "$GITHUB_REPO"
    gh variable set TF_STATE_STORAGE_ACCOUNT --body "$TF_STATE_STORAGE_ACCOUNT" --repo "$GITHUB_REPO"
    echo "✓ All GitHub variables successfully synchronized!"
else
    echo "Note: gh CLI is not available or not authenticated."
    echo "Please set these Variables in your GitHub Repository ($GITHUB_REPO -> Settings -> Secrets and variables -> Actions -> Variables):"
    echo "  AZURE_CLIENT_ID:           $APP_ID"
    echo "  AZURE_TENANT_ID:           $TENANT_ID"
    echo "  AZURE_SUBSCRIPTION_ID:     $SUBSCRIPTION_ID"
    echo "  TF_STATE_RESOURCE_GROUP:   $TF_STATE_RG"
    echo "  TF_STATE_STORAGE_ACCOUNT:  $TF_STATE_STORAGE_ACCOUNT"
fi

echo ""
echo "=================================================================="
echo "✓ Azure OIDC & Terraform Remote State setup completed successfully!"
echo "You can now trigger the deployment pipeline with:"
echo "  gh workflow run \"Deploy dev\" --repo $GITHUB_REPO"
echo "=================================================================="
