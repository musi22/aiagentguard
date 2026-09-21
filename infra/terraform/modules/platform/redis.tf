# Azure Managed Redis is the current service behind Microsoft.Cache/redisEnterprise.
# API 2025-07-01 is used because it introduces explicit publicNetworkAccess.
resource "azapi_resource" "managed_redis" {
  count     = var.managed_redis_enabled ? 1 : 0
  type      = "Microsoft.Cache/redisEnterprise@2025-07-01"
  parent_id = azurerm_resource_group.main.id
  name      = "redis-${local.prefix}-${local.suffix}"
  location  = azurerm_resource_group.main.location
  tags      = local.tags

  body = {
    properties = {
      encryption          = {}
      highAvailability    = var.production_mode ? "Enabled" : "Disabled"
      minimumTlsVersion   = "1.2"
      publicNetworkAccess = var.production_mode ? "Disabled" : "Enabled"
    }
    sku = {
      name = "Balanced_B0"
    }
  }

  schema_validation_enabled = false
  response_export_values    = ["properties.hostName"]
}

resource "azapi_resource" "managed_redis_database" {
  count     = var.managed_redis_enabled ? 1 : 0
  type      = "Microsoft.Cache/redisEnterprise/databases@2025-07-01"
  parent_id = azapi_resource.managed_redis[0].id
  name      = "default"

  body = {
    properties = {
      accessKeysAuthentication = "Disabled"
      clientProtocol           = "Encrypted"
      clusteringPolicy         = "EnterpriseCluster"
      evictionPolicy           = "VolatileLRU"
      modules                  = []
      port                     = 10000
    }
  }

  schema_validation_enabled = false
}

# Access-policy assignments use Microsoft Entra identities and are serialized to
# avoid the service-side race documented for concurrent assignments.
resource "azapi_resource" "redis_api_access" {
  count     = var.managed_redis_enabled ? 1 : 0
  type      = "Microsoft.Cache/redisEnterprise/databases/accessPolicyAssignments@2025-07-01"
  parent_id = azapi_resource.managed_redis_database[0].id
  name      = "agentguard-api"
  body = {
    properties = {
      accessPolicyName = "default"
      user = {
        objectId = azurerm_user_assigned_identity.app["api"].principal_id
      }
    }
  }
  schema_validation_enabled = false
}

resource "azapi_resource" "redis_gateway_access" {
  count     = var.managed_redis_enabled ? 1 : 0
  type      = "Microsoft.Cache/redisEnterprise/databases/accessPolicyAssignments@2025-07-01"
  parent_id = azapi_resource.managed_redis_database[0].id
  name      = "agentguard-gateway"
  body = {
    properties = {
      accessPolicyName = "default"
      user = {
        objectId = azurerm_user_assigned_identity.app["gateway"].principal_id
      }
    }
  }
  schema_validation_enabled = false
  depends_on                = [azapi_resource.redis_api_access]
}

resource "azapi_resource" "redis_worker_access" {
  count     = var.managed_redis_enabled ? 1 : 0
  type      = "Microsoft.Cache/redisEnterprise/databases/accessPolicyAssignments@2025-07-01"
  parent_id = azapi_resource.managed_redis_database[0].id
  name      = "agentguard-worker"
  body = {
    properties = {
      accessPolicyName = "default"
      user = {
        objectId = azurerm_user_assigned_identity.app["worker"].principal_id
      }
    }
  }
  schema_validation_enabled = false
  depends_on                = [azapi_resource.redis_gateway_access]
}

resource "azurerm_private_dns_zone" "redis" {
  count               = var.production_mode && var.managed_redis_enabled ? 1 : 0
  name                = "privatelink.redis.azure.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "redis" {
  count                 = var.production_mode && var.managed_redis_enabled ? 1 : 0
  name                  = "redis-vnet-link"
  private_dns_zone_name = azurerm_private_dns_zone.redis[0].name
  resource_group_name   = azurerm_resource_group.main.name
  virtual_network_id    = azurerm_virtual_network.main.id
}

resource "azurerm_private_endpoint" "redis" {
  count               = var.production_mode && var.managed_redis_enabled ? 1 : 0
  name                = "pe-${local.prefix}-redis"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.private_endpoints[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "redis"
    private_connection_resource_id = azapi_resource.managed_redis[0].id
    subresource_names              = ["redisEnterprise"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "redis"
    private_dns_zone_ids = [azurerm_private_dns_zone.redis[0].id]
  }
}
