resource "azurerm_container_app_environment" "main" {
  name                           = "cae-${local.prefix}-${local.suffix}"
  location                       = azurerm_resource_group.main.location
  resource_group_name            = azurerm_resource_group.main.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.main.id
  infrastructure_subnet_id       = azurerm_subnet.container_apps.id
  internal_load_balancer_enabled = var.production_mode
  public_network_access          = var.production_mode ? "Disabled" : "Enabled"
  zone_redundancy_enabled        = var.production_mode
  tags                           = local.tags

  dynamic "workload_profile" {
    for_each = var.production_mode ? [1] : []
    content {
      name                  = "Consumption"
      workload_profile_type = "Consumption"
      minimum_count         = 0
      maximum_count         = 20
    }
  }
}

resource "azurerm_container_app" "api" {
  name                         = "${local.prefix}-api"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Multiple"
  max_inactive_revisions       = 5
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app["api"].id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.app["api"].id
  }

  template {
    min_replicas = local.min_replicas
    max_replicas = var.production_mode ? var.api_max_replicas : 2

    container {
      name   = "api"
      image  = "${azurerm_container_registry.main.login_server}/agentguard-api:${var.image_tag}"
      cpu    = var.production_mode ? 1.0 : 0.5
      memory = var.production_mode ? "2Gi" : "1Gi"

      dynamic "env" {
        for_each = local.identity_env.api
        content {
          name  = env.key
          value = env.value
        }
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = 8000
        path                    = "/health"
        interval_seconds        = 30
        timeout                 = 5
        failure_count_threshold = 3
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = 8000
        path                    = "/ready"
        interval_seconds        = 10
        timeout                 = 5
        failure_count_threshold = 3
      }
    }

    http_scale_rule {
      name                = "http-concurrency"
      concurrent_requests = 50
    }
  }

  ingress {
    external_enabled           = true
    target_port                = 8000
    allow_insecure_connections = false
    transport                  = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

resource "azurerm_container_app" "gateway" {
  name                         = "${local.prefix}-gateway"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Multiple"
  max_inactive_revisions       = 5
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app["gateway"].id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.app["gateway"].id
  }

  template {
    min_replicas = local.min_replicas
    max_replicas = var.production_mode ? var.gateway_max_replicas : 2

    container {
      name   = "gateway"
      image  = "${azurerm_container_registry.main.login_server}/agentguard-gateway:${var.image_tag}"
      cpu    = var.production_mode ? 1.0 : 0.5
      memory = var.production_mode ? "2Gi" : "1Gi"

      dynamic "env" {
        for_each = merge(local.identity_env.gateway, { AGENTGUARD_API_INTERNAL_URL = "https://${azurerm_container_app.api.ingress[0].fqdn}" })
        content {
          name  = env.key
          value = env.value
        }
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = 8001
        path                    = "/health"
        interval_seconds        = 30
        timeout                 = 5
        failure_count_threshold = 3
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = 8001
        path                    = "/ready"
        interval_seconds        = 10
        timeout                 = 5
        failure_count_threshold = 3
      }
    }

    http_scale_rule {
      name                = "http-concurrency"
      concurrent_requests = 50
    }
  }

  ingress {
    external_enabled           = true
    target_port                = 8001
    allow_insecure_connections = false
    transport                  = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

resource "azurerm_container_app_job" "worker" {
  name                         = "${local.prefix}-worker"
  location                     = azurerm_resource_group.main.location
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  replica_timeout_in_seconds   = 300
  replica_retry_limit          = 2
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app["worker"].id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.app["worker"].id
  }

  schedule_trigger_config {
    cron_expression          = "* * * * *"
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name    = "worker"
      image   = "${azurerm_container_registry.main.login_server}/agentguard-worker:${var.image_tag}"
      cpu     = 0.5
      memory  = "1Gi"
      command = ["python", "-m", "agentguard_worker.main"]

      dynamic "env" {
        for_each = local.identity_env.worker
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull]
}

resource "azurerm_container_app_job" "migration" {
  name                         = "${local.prefix}-migration"
  location                     = azurerm_resource_group.main.location
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 0
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app["migration"].id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.app["migration"].id
  }

  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name    = "migration"
      image   = "${azurerm_container_registry.main.login_server}/agentguard-api:${var.image_tag}"
      cpu     = 0.5
      memory  = "1Gi"
      command = ["python", "scripts/bootstrap_database.py"]

      dynamic "env" {
        for_each = merge(local.identity_env.migration, {
          DATABASE_API_PRINCIPAL    = azurerm_user_assigned_identity.app["api"].name
          DATABASE_WORKER_PRINCIPAL = azurerm_user_assigned_identity.app["worker"].name
        })
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  depends_on = [azurerm_role_assignment.acr_pull, azurerm_postgresql_flexible_server_active_directory_administrator.migration]
}
