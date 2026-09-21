resource "azurerm_storage_account" "audit" {
  name                            = local.storage_name
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = var.production_mode ? "ZRS" : "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false
  public_network_access_enabled   = true
  tags                            = local.tags

  blob_properties {
    versioning_enabled       = true
    change_feed_enabled      = var.production_mode
    last_access_time_enabled = var.production_mode
    delete_retention_policy {
      days = var.production_mode ? 30 : 7
    }
    container_delete_retention_policy {
      days = var.production_mode ? 30 : 7
    }
  }

  network_rules {
    default_action = var.production_mode ? "Deny" : "Allow"
    bypass         = ["AzureServices", "Logging", "Metrics"]
  }
}

resource "azurerm_storage_container" "audit_archive" {
  name                  = "audit-archive"
  storage_account_id    = azurerm_storage_account.audit.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "audit" {
  storage_account_id = azurerm_storage_account.audit.id

  rule {
    name    = "audit-retention"
    enabled = true
    filters {
      prefix_match = ["audit-archive/"]
      blob_types   = ["blockBlob"]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = var.production_mode ? 30 : 7
        tier_to_archive_after_days_since_modification_greater_than = var.production_mode ? 90 : 30
        delete_after_days_since_modification_greater_than          = var.production_mode ? 2555 : 90
      }
    }
  }
}

resource "azurerm_role_assignment" "storage_blob_contributor" {
  for_each = { worker = azurerm_user_assigned_identity.app["worker"] }

  scope                = azurerm_storage_account.audit.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value.principal_id
}

resource "azurerm_private_endpoint" "blob" {
  count               = var.production_mode ? 1 : 0
  name                = "pe-${local.prefix}-blob"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "blob"
    private_connection_resource_id = azurerm_storage_account.audit.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob[0].id]
  }
}
