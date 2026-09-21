resource "azurerm_static_web_app" "dashboard" {
  name                = local.static_web_app_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku_tier            = local.static_web_app_sku
  sku_size            = local.static_web_app_sku
  tags                = local.tags
}

