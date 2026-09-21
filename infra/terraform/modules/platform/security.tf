resource "azurerm_user_assigned_identity" "app" {
  for_each = toset(["api", "gateway", "worker", "migration"])

  name                = "id-${local.prefix}-${each.key}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_key_vault" "main" {
  name                          = local.key_vault_name
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = var.production_mode
  soft_delete_retention_days    = var.production_mode ? 90 : 7
  public_network_access_enabled = true
  tags                          = local.tags

  network_acls {
    bypass         = "AzureServices"
    default_action = var.production_mode ? "Deny" : "Allow"
  }
}

# ARM child resources avoid a public data-plane call from a hosted CI runner
# after the production vault network ACL changes to Deny.
resource "azapi_resource" "database_password" {
  type      = "Microsoft.KeyVault/vaults/secrets@2024-11-01"
  parent_id = azurerm_key_vault.main.id
  name      = "database-password"
  body = {
    properties = {
      value       = var.database_admin_password
      contentType = "application/x-agentguard-secret"
      attributes  = { enabled = true }
    }
  }
  schema_validation_enabled = false
}

resource "azapi_resource" "payload_encryption_key" {
  type      = "Microsoft.KeyVault/vaults/secrets@2024-11-01"
  parent_id = azurerm_key_vault.main.id
  name      = "payload-encryption-key"
  body = {
    properties = {
      value       = var.payload_encryption_key
      contentType = "application/x-agentguard-fernet-key"
      attributes  = { enabled = true }
    }
  }
  schema_validation_enabled = false
}

resource "azurerm_role_assignment" "key_vault_secrets_user" {
  for_each = {
    api    = azurerm_user_assigned_identity.app["api"]
    worker = azurerm_user_assigned_identity.app["worker"]
  }

  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.value.principal_id
}

resource "azurerm_private_endpoint" "key_vault" {
  count               = var.production_mode ? 1 : 0
  name                = "pe-${local.prefix}-key-vault"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "key-vault"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "key-vault"
    private_dns_zone_ids = [azurerm_private_dns_zone.key_vault[0].id]
  }
}
