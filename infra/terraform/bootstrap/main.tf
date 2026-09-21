data "azurerm_subscription" "target" {
  subscription_id = var.subscription_id
}

data "azurerm_client_config" "current" {}

resource "azuread_application" "github" {
  display_name     = "agentguard-github-actions"
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "github" {
  client_id                    = azuread_application.github.client_id
  app_role_assignment_required = false
}

resource "azuread_application_federated_identity_credential" "environment" {
  for_each = toset(["dev", "staging", "production"])

  application_id = azuread_application.github.id
  display_name   = "github-${each.key}"
  description    = "GitHub Actions OIDC for AgentGuard ${each.key} environment"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_organization}/${var.github_repository}:environment:${each.key}"
}

resource "azuread_application_federated_identity_credential" "pull_request" {
  application_id = azuread_application.github.id
  display_name   = "github-pull-request"
  description    = "Read-only validation identity subject; do not grant write roles in a separate production subscription."
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:${var.github_organization}/${var.github_repository}:pull_request"
}

# Contributor provisions service resources but cannot grant data-plane access.
resource "azurerm_role_assignment" "contributor" {
  scope                = data.azurerm_subscription.target.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.github.object_id
}

# Terraform creates narrowly scoped role assignments for application identities.
# In a mature platform, replace this subscription scope with pre-created resource
# group scopes and a custom role limited to roleAssignments/write/delete.
resource "azurerm_role_assignment" "rbac_admin" {
  scope                = data.azurerm_subscription.target.id
  role_definition_name = "Role Based Access Control Administrator"
  principal_id         = azuread_service_principal.github.object_id
}

