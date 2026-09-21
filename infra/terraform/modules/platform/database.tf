resource "azurerm_postgresql_flexible_server" "main" {
  name                          = local.postgres_name
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  version                       = "16"
  administrator_login           = var.database_admin_username
  administrator_password        = var.database_admin_password
  sku_name                      = var.production_mode ? "GP_Standard_D4s_v3" : "B_Standard_B1ms"
  storage_mb                    = var.production_mode ? 131072 : 32768
  storage_tier                  = var.production_mode ? "P10" : null
  backup_retention_days         = var.production_mode ? 35 : 7
  geo_redundant_backup_enabled  = false
  public_network_access_enabled = false
  delegated_subnet_id           = azurerm_subnet.postgres.id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  zone                          = var.production_mode ? "1" : null
  tags                          = local.tags

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = true
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }

  dynamic "high_availability" {
    for_each = var.production_mode ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = "2"
    }
  }

  maintenance_window {
    day_of_week  = 0
    start_hour   = 2
    start_minute = 0
  }

  lifecycle {
    prevent_destroy = false
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "migration" {
  server_name         = azurerm_postgresql_flexible_server.main.name
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = azurerm_user_assigned_identity.app["migration"].principal_id
  principal_name      = azurerm_user_assigned_identity.app["migration"].name
  principal_type      = "ServicePrincipal"
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "agentguard"
  server_id = azurerm_postgresql_flexible_server.main.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_configuration" "require_tls" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "on"
}

resource "azurerm_postgresql_flexible_server_configuration" "log_connections" {
  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "on"
}
