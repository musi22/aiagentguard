# Deploy AgentGuard to Azure

This guide deploys real AgentGuard services: a static Next.js dashboard, FastAPI
API and gateway, a scheduled worker, PostgreSQL, audit storage, Key Vault, and
monitoring. Development and staging use startup mode. Production adds private
networking, PostgreSQL zone-redundant HA, Azure Managed Redis, Front Door Premium,
WAF, and a two-replica floor for both online services.

No Azure subscription is modified merely by cloning this repository. An apply is
an intentional, billable operation.

## 1. Prerequisites

Install Terraform 1.8+, Azure CLI, Node.js 22, and Docker. You need permission to
create resources, role assignments, and an Entra application. Select the target:

```sh
az login
az account set --subscription "<subscription-id>"
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.Cache
az provider register --namespace Microsoft.Cdn
az provider register --namespace Microsoft.ContainerRegistry
az provider register --namespace Microsoft.DBforPostgreSQL
az provider register --namespace Microsoft.Insights
az provider register --namespace Microsoft.KeyVault
az provider register --namespace Microsoft.Storage
```

Availability and quotas differ by region. Confirm that the chosen region supports
PostgreSQL zone-redundant HA and Azure Managed Redis before a production apply.

## 2. Automated Azure Setup (Recommended)

To automatically create the Terraform state storage account, register the Microsoft Entra application with federated OIDC credentials for GitHub Actions, and configure all GitHub repository variables with a single command:

In Azure Cloud Shell (`https://shell.azure.com`) or bash:
```bash
./scripts/setup_azure_oidc.sh
```

Or in PowerShell:
```powershell
.\scripts\setup_azure_oidc.ps1
```

Once executed, trigger the automated deployment pipeline from GitHub Actions:
```bash
gh workflow run "Deploy dev" --repo musi22/aiagentguard
```

## 3. Manual Remote State & App Registration (Alternative)

State contains sensitive values even though Terraform redacts them from terminal
output. Put it in a dedicated account with Entra authorization and versioning.
Choose a globally unique lowercase account name:

```sh
az group create --name rg-agentguard-tfstate --location centralindia
az storage account create \
  --name agentguardtfstateUNIQUE \
  --resource-group rg-agentguard-tfstate \
  --location centralindia \
  --sku Standard_LRS \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false
state_id=$(az storage account show --name agentguardtfstateUNIQUE --resource-group rg-agentguard-tfstate --query id -o tsv)
principal_id=$(az ad signed-in-user show --query id -o tsv)
az role assignment create --assignee-object-id "$principal_id" --assignee-principal-type User \
  --role "Storage Blob Data Contributor" --scope "$state_id"
az storage container create --name tfstate --account-name agentguardtfstateUNIQUE --auth-mode login
az storage account blob-service-properties update --account-name agentguardtfstateUNIQUE \
  --enable-versioning true --enable-change-feed true --auth-mode login
```

Copy the selected environment's `backend.hcl.example` to `backend.hcl` and enter
that state account. Never commit `backend.hcl`, `terraform.tfvars`, a plan file,
or state.

## 3. Configure GitHub OIDC

Bootstrap creates an Entra application, service principal, and federated
credentials for GitHub environments named `dev`, `staging`, and `production`.
It never creates a client secret.

```sh
cp infra/terraform/bootstrap/terraform.tfvars.example infra/terraform/bootstrap/terraform.tfvars
terraform -chdir=infra/terraform/bootstrap init
terraform -chdir=infra/terraform/bootstrap plan -out=tfplan
terraform -chdir=infra/terraform/bootstrap apply tfplan
terraform -chdir=infra/terraform/bootstrap output
```

Create those three GitHub environments. Require reviewers on `production` and
restrict it to release tags. Add these non-secret environment variables:

```text
AZURE_CLIENT_ID
AZURE_TENANT_ID
AZURE_SUBSCRIPTION_ID
AZURE_UNIQUE_SUFFIX
AZURE_BUDGET_AMOUNT
FINOPS_EMAIL
OPERATIONS_EMAIL
TF_STATE_RESOURCE_GROUP
TF_STATE_STORAGE_ACCOUNT
```

Add two protected environment secrets:

```text
DATABASE_ADMIN_PASSWORD
PAYLOAD_ENCRYPTION_KEY
```

Generate the Fernet key locally with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
The workflow exchanges GitHub's short-lived OIDC token for an Azure token. It
does not store a service-principal password.

The bootstrap identity has subscription Contributor and RBAC Administrator
because a first apply creates resource groups and application role assignments.
A mature platform should replace these with a custom deployment role scoped to
pre-created environment resource groups.

## 4. Configure Terraform

```sh
cp infra/terraform/environments/dev/backend.hcl.example infra/terraform/environments/dev/backend.hcl
cp infra/terraform/environments/dev/terraform.tfvars.example infra/terraform/environments/dev/terraform.tfvars
export TF_VAR_database_admin_password='<strong-random-password>'
export TF_VAR_payload_encryption_key='<fernet-key>'
terraform -chdir=infra/terraform/environments/dev init -backend-config=backend.hcl
terraform -chdir=infra/terraform/environments/dev fmt -check
terraform -chdir=infra/terraform/environments/dev validate
terraform -chdir=infra/terraform/environments/dev plan -var-file=terraform.tfvars
```

Replace the documentation-only IP `203.0.113.x` with exact trusted human/CI
egress IPs or leave `postgresql_allowed_ips` empty. Terraform also creates exact
firewall rules from the API, worker, and migration Job egress addresses exported
by Container Apps. The configuration rejects `0.0.0.0`; it never enables the
broad Azure-services PostgreSQL firewall rule.

The globally unique suffix must be stable. Changing it replaces ACR, Key Vault,
Storage, PostgreSQL, and Static Web Apps resources.

## 5. Provision and deploy development

The deployment script first targets ACR so the first real application images can
be built. It uses Azure Container Registry Tasks to build three immutable SHA-
tagged images, applies only the migration job and its infrastructure dependencies,
runs that job, waits for a successful result, and only then applies the full plan
that creates or shifts online revisions. Finally, it builds
and publishes the static dashboard using a deployment token retrieved just in
time through the OIDC-authenticated Azure session.

```sh
./scripts/deploy.sh dev "$(git rev-parse HEAD)"
# PowerShell:
./scripts/deploy.ps1 -Environment dev -ImageTag "$(git rev-parse HEAD)"
```

The dev workflow does the same after CI succeeds on `main`. Do not use `latest`
for production; Terraform and the scripts reject it.

## 6. Database migrations

Alembic runs in the `ag-<environment>-migration` manual Container Apps Job using
the API image. It obtains the database password from Key Vault through the API's
managed identity. A failed migration stops deployment before online service
restarts. Prefer backward-compatible expand/migrate/contract changes:

1. add nullable/new schema;
2. deploy compatible code;
3. backfill asynchronously;
4. enforce constraints in a later release;
5. remove old columns only after rollback windows expire.

Never implement rollback by blindly downgrading a destructive migration. Restore
to a new PostgreSQL server and deploy the last compatible image when data changed.

## 7. Configure application secrets

Terraform creates only `database-password` and `payload-encryption-key`. Add
integration secrets without printing their values:

```sh
az keyvault secret set --vault-name <vault> --name stripe-secret-key --value "$STRIPE_SECRET_KEY" --output none
az keyvault secret set --vault-name <vault> --name stripe-webhook-secret --value "$STRIPE_WEBHOOK_SECRET" --output none
az keyvault secret set --vault-name <vault> --name slack-bot-token --value "$SLACK_BOT_TOKEN" --output none
az keyvault secret set --vault-name <vault> --name slack-signing-secret --value "$SLACK_SIGNING_SECRET" --output none
```

In production, run secret administration from a VNet-connected runner or approved
private workstation because the vault denies public data-plane traffic. API,
gateway, and worker identities receive only `Key Vault Secrets User`; no service
gets Key Vault administrator rights.

## 8. Dashboard, routes, and domains

`apps/web/next.config.mjs` must use static export so `npm run build` produces
`apps/web/out`. Startup environments expose the Static Web App and Container Apps
hostnames directly. Production creates three Front Door endpoints—dashboard,
API, and gateway—each protected by the WAF. API and gateway origins use Front Door
Premium Private Link to an internal Container Apps environment; the deployment
script approves the generated connection requests without a portal click. Configure custom DNS and certificates
after adding explicit `azurerm_cdn_frontdoor_custom_domain` resources for owned
domains; do not point DNS before Azure validates domain ownership.

By default, Terraform supplies the generated Front Door API hostname as
`PUBLIC_URL`, the generated dashboard endpoint as `WEB_URL`, and the dashboard as
the only CORS origin. After custom-domain resources and DNS ownership validation
are in place, set `public_url`, `web_url`, and `cors_origins` in the protected
environment configuration. Set Microsoft Entra External ID/OIDC callback URLs to the final public hostname.
Keep `SESSION_SECURE=true` in production and make CORS an exact origin list.

## 9. Monitoring and verification

All services receive the Application Insights connection string. Container Apps
logs flow to Log Analytics. The baseline alerts cover gateway 5xx responses and
latency; the application should publish custom metrics for authorization latency,
approval backlog, budget anomalies, and worker failures, then add metric alerts
against those names.

```sh
terraform -chdir=infra/terraform/environments/dev output
curl --fail "$(terraform -chdir=infra/terraform/environments/dev output -raw api_url)/health"
curl --fail "$(terraform -chdir=infra/terraform/environments/dev output -raw gateway_url)/ready"
az containerapp job execution list --resource-group rg-agentguard-dev --name ag-dev-worker -o table
```

Verify a real allow, approval, deny, budget-exceeded, rate-limit, and kill-switch
flow and confirm each has a correlated audit event before promotion.

## 10. Release production

Push a semantic version tag such as `v1.0.0`. The release workflow reruns quality
checks, deploys the same commit SHA to staging, runs Playwright, pauses at the
protected `production` environment, then provisions/builds/migrates/deploys prod.
The SHA, not `latest`, is the runtime image tag.

Production is intentionally billable: Front Door Premium/WAF, Premium ACR,
zone-redundant PostgreSQL, minimum two API/gateway replicas, private endpoints,
and Azure Managed Redis. Review the plan and pricing before approval.

## Authoritative Azure references

- [Container Apps Jobs and UTC cron schedules](https://learn.microsoft.com/azure/container-apps/jobs)
- [Front Door Premium to internal Container Apps with Private Link](https://learn.microsoft.com/azure/container-apps/front-door-custom-virtual-network-private-link)
- [Azure Managed Redis ARM/AzAPI resource](https://learn.microsoft.com/azure/templates/microsoft.cache/2025-07-01/redisenterprise)
- [Managed Redis Microsoft Entra authentication](https://learn.microsoft.com/azure/redis/entra-for-authentication)
- [Azure Private Endpoint DNS zones](https://learn.microsoft.com/azure/private-link/private-endpoint-dns)
- [Static Web Apps hosting plans](https://learn.microsoft.com/azure/static-web-apps/plans)
- [GitHub Actions OIDC with Azure](https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect)
