#!/usr/bin/env sh
set -eu

environment="${1:-}"
image_tag="${2:-}"
case "$environment" in dev|staging|prod) ;; *) echo "Usage: $0 dev|staging|prod <immutable-image-tag>" >&2; exit 2;; esac
if [ -z "$image_tag" ] || { [ "$environment" = prod ] && [ "$image_tag" = latest ]; }; then
  echo "An immutable image tag is required; production cannot use latest." >&2
  exit 2
fi

tf_dir="infra/terraform/environments/$environment"
backend_config="${BACKEND_CONFIG:-backend.hcl}"
tfvars_file="${TF_VARS_FILE:-terraform.tfvars}"
terraform -chdir="$tf_dir" init -backend-config="$backend_config"

if [ -f "$tf_dir/$tfvars_file" ]; then
  terraform -chdir="$tf_dir" apply -auto-approve -var-file="$tfvars_file" -var="image_tag=$image_tag" \
    -target=module.agentguard.azurerm_container_registry.main
else
  terraform -chdir="$tf_dir" apply -auto-approve -var="image_tag=$image_tag" \
    -target=module.agentguard.azurerm_container_registry.main
fi

registry="$(terraform -chdir="$tf_dir" output -raw container_registry_name 2>/dev/null || az acr list --resource-group "rg-agentguard-$environment" --query '[0].name' -o tsv)"
for service in api gateway worker; do
  az acr build --registry "$registry" --image "agentguard-$service:$image_tag" --target "$service" .
done

if [ -f "$tf_dir/$tfvars_file" ]; then
  terraform -chdir="$tf_dir" plan -var-file="$tfvars_file" -var="image_tag=$image_tag" \
    -target=module.agentguard.azurerm_container_app_job.migration -out=migration.tfplan
else
  terraform -chdir="$tf_dir" plan -var="image_tag=$image_tag" \
    -target=module.agentguard.azurerm_container_app_job.migration -out=migration.tfplan
fi
terraform -chdir="$tf_dir" apply migration.tfplan

resource_group="$(terraform -chdir="$tf_dir" output -raw resource_group_name)"
migration_job="$(terraform -chdir="$tf_dir" output -raw migration_job_name)"
execution="$(az containerapp job start --resource-group "$resource_group" --name "$migration_job" --query name -o tsv)"

while :; do
  status="$(az containerapp job execution show --resource-group "$resource_group" --name "$migration_job" --job-execution-name "$execution" --query properties.status -o tsv)"
  case "$status" in
    Succeeded) break ;;
    Failed|Stopped|Degraded) echo "Migration execution $execution failed with status $status" >&2; exit 1 ;;
  esac
  sleep 10
done

if [ -f "$tf_dir/$tfvars_file" ]; then
  terraform -chdir="$tf_dir" plan -var-file="$tfvars_file" -var="image_tag=$image_tag" -out=tfplan
else
  terraform -chdir="$tf_dir" plan -var="image_tag=$image_tag" -out=tfplan
fi
terraform -chdir="$tf_dir" apply tfplan

if [ "$environment" = "prod" ]; then
  container_environment="$(terraform -chdir="$tf_dir" output -raw container_app_environment_name)"
  az network private-endpoint-connection list \
    --resource-group "$resource_group" \
    --name "$container_environment" \
    --type Microsoft.App/managedEnvironments \
    --query "[?properties.privateLinkServiceConnectionState.status=='Pending'].id" -o tsv |
  while IFS= read -r connection_id; do
    [ -n "$connection_id" ] && az network private-endpoint-connection approve --id "$connection_id" --description "Approved by AgentGuard deployment"
  done
fi

static_web_app="$(terraform -chdir="$tf_dir" output -raw static_web_app_name)"
api_url="$(terraform -chdir="$tf_dir" output -raw api_url)"
gateway_url="$(terraform -chdir="$tf_dir" output -raw gateway_url)"
(cd apps/web && NEXT_PUBLIC_API_URL="$api_url" NEXT_PUBLIC_GATEWAY_URL="$gateway_url" npm install && npm run build)
deployment_token="$(az staticwebapp secrets list --resource-group "$resource_group" --name "$static_web_app" --query properties.apiKey -o tsv)"
npx --yes @azure/static-web-apps-cli deploy apps/web/out --deployment-token "$deployment_token" --env production

echo "AgentGuard $environment deployed with image tag $image_tag; migrations succeeded first."
