output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "container_registry_name" {
  value = azurerm_container_registry.main.name
}

output "container_registry_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "container_app_environment_name" {
  value = azurerm_container_app_environment.main.name
}

output "api_container_app_name" {
  value = azurerm_container_app.api.name
}

output "gateway_container_app_name" {
  value = azurerm_container_app.gateway.name
}

output "worker_job_name" {
  value = azurerm_container_app_job.worker.name
}

output "migration_job_name" {
  value = azurerm_container_app_job.migration.name
}

output "api_url" {
  value = local.effective_api_url
}

output "gateway_url" {
  value = local.effective_gateway_url
}

output "dashboard_hostname" {
  value = azurerm_static_web_app.dashboard.default_host_name
}

output "dashboard_url" {
  value = local.effective_web_url
}

output "static_web_app_name" {
  value = azurerm_static_web_app.dashboard.name
}

output "key_vault_url" {
  value = azurerm_key_vault.main.vault_uri
}

output "postgresql_hostname" {
  value = azurerm_postgresql_flexible_server.main.fqdn
}

output "managed_redis_hostname" {
  value = var.managed_redis_enabled ? "${azapi_resource.managed_redis[0].name}.${var.location}.redis.azure.net" : null
}

output "front_door_endpoints" {
  value = {
    for key, endpoint in azurerm_cdn_frontdoor_endpoint.endpoint : key => endpoint.host_name
  }
}

output "managed_identity_client_ids" {
  value = {
    for key, identity in azurerm_user_assigned_identity.app : key => identity.client_id
  }
}
