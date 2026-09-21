resource "azurerm_container_registry" "main" {
  name                          = local.acr_name
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  sku                           = var.production_mode ? "Premium" : "Basic"
  admin_enabled                 = false
  public_network_access_enabled = true
  zone_redundancy_enabled       = var.production_mode
  anonymous_pull_enabled        = false
  tags                          = local.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  for_each = azurerm_user_assigned_identity.app

  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = each.value.principal_id
}

