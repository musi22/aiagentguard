output "azure_client_id" {
  value = azuread_application.github.client_id
}

output "azure_tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "azure_subscription_id" {
  value = data.azurerm_subscription.target.subscription_id
}

