locals {
  prefix = "ag-${var.environment}"
  suffix = var.unique_suffix

  tags = {
    project        = "agentguard"
    environment    = var.environment
    owner          = "agentguard"
    cost-center    = "agentguard"
    managed-by     = "terraform"
    repository     = var.github_repository
    operating-mode = var.production_mode ? "production" : "startup"
  }

  resource_group_name = "rg-agentguard-${var.environment}"
  acr_name            = "ag${var.environment}${local.suffix}acr"
  key_vault_name      = "kv-ag-${var.environment}-${local.suffix}"
  storage_name        = "ag${var.environment}${local.suffix}st"
  postgres_name       = "psql-ag-${var.environment}-${local.suffix}"
  static_web_app_name = "swa-agentguard-${var.environment}-${local.suffix}"

  min_replicas       = var.production_mode ? 2 : 0
  log_retention_days = coalesce(var.log_retention_days, var.production_mode ? 90 : 30)
  static_web_app_sku = coalesce(var.static_web_app_sku, var.production_mode ? "Standard" : "Free")

  generated_api_url = var.front_door_enabled ? (
    "https://${azurerm_cdn_frontdoor_endpoint.endpoint["api"].host_name}"
    ) : (
    "https://${local.prefix}-api.${azurerm_container_app_environment.main.default_domain}"
  )
  generated_web_url = var.front_door_enabled ? (
    "https://${azurerm_cdn_frontdoor_endpoint.endpoint["dashboard"].host_name}"
    ) : (
    "https://${azurerm_static_web_app.dashboard.default_host_name}"
  )
  effective_api_url = coalesce(var.public_url, local.generated_api_url)
  effective_web_url = coalesce(var.web_url, local.generated_web_url)
  effective_gateway_url = var.front_door_enabled ? (
    "https://${azurerm_cdn_frontdoor_endpoint.endpoint["gateway"].host_name}"
    ) : (
    "https://${local.prefix}-gateway.${azurerm_container_app_environment.main.default_domain}"
  )

  common_env = {
    ENVIRONMENT                           = var.environment == "prod" ? "production" : (var.environment == "staging" ? "staging" : "development")
    DATABASE_HOST                         = azurerm_postgresql_flexible_server.main.fqdn
    DATABASE_NAME                         = azurerm_postgresql_flexible_server_database.main.name
    DATABASE_AUTH                         = "entra"
    KEY_VAULT_URL                         = azurerm_key_vault.main.vault_uri
    AUDIT_STORAGE_ACCOUNT_URL             = azurerm_storage_account.audit.primary_blob_endpoint
    APPLICATIONINSIGHTS_CONNECTION_STRING = azurerm_application_insights.main.connection_string
    CORS_ORIGINS                          = join(",", length(var.cors_origins) > 0 ? var.cors_origins : [local.effective_web_url])
    PUBLIC_URL                            = local.effective_api_url
    WEB_URL                               = local.effective_web_url
    SESSION_SECURE                        = var.environment == "dev" ? "false" : "true"
    REDIS_HOST                            = var.managed_redis_enabled ? "${azapi_resource.managed_redis[0].name}.${var.location}.redis.azure.net" : ""
    REDIS_PORT                            = var.managed_redis_enabled ? "10000" : ""
    REDIS_SSL                             = var.managed_redis_enabled ? "true" : "false"
    REDIS_AUTH                            = var.managed_redis_enabled ? "entra" : "none"
  }

  identity_env = {
    for key, identity in azurerm_user_assigned_identity.app : key => merge(local.common_env, {
      AZURE_CLIENT_ID = identity.client_id
      DATABASE_USER   = identity.name
    })
  }
}

resource "terraform_data" "mode_guard" {
  lifecycle {
    precondition {
      condition     = var.startup_mode != var.production_mode
      error_message = "Exactly one of startup_mode and production_mode must be true."
    }
    precondition {
      condition     = !var.production_mode || var.front_door_enabled
      error_message = "front_door_enabled must be true in production mode."
    }
    precondition {
      condition     = !var.production_mode || var.managed_redis_enabled
      error_message = "managed_redis_enabled must be true in production mode."
    }
    precondition {
      condition     = length(var.postgresql_allowed_ips) == 0
      error_message = "PostgreSQL is private in both modes; public firewall rules are not accepted."
    }
  }
}
