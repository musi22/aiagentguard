resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.prefix}-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = local.log_retention_days
  daily_quota_gb      = var.production_mode ? 10 : 0.5
  tags                = local.tags
}

resource "azurerm_application_insights" "main" {
  name                = "appi-${local.prefix}-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"
  retention_in_days   = local.log_retention_days
  tags                = local.tags
}

resource "azurerm_monitor_action_group" "operations" {
  name                = "ag-${local.prefix}-ops"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "agops"
  tags                = local.tags

  email_receiver {
    name                    = "agentguard-operations"
    email_address           = var.alert_action_group_email
    use_common_alert_schema = true
  }
}

resource "azurerm_monitor_metric_alert" "gateway_requests" {
  name                = "${local.prefix}-gateway-server-errors"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_container_app.gateway.id]
  description         = "Gateway returned server errors."
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"
  tags                = local.tags

  criteria {
    metric_namespace = "Microsoft.App/containerApps"
    metric_name      = "Requests"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 5

    dimension {
      name     = "statusCodeCategory"
      operator = "Include"
      values   = ["5xx"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.operations.id
  }
}

resource "azurerm_monitor_metric_alert" "gateway_latency" {
  name                = "${local.prefix}-gateway-latency"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_container_app.gateway.id]
  description         = "Gateway p95 response time is above 500 ms."
  severity            = 2
  frequency           = "PT1M"
  window_size         = "PT5M"
  tags                = local.tags

  criteria {
    metric_namespace = "Microsoft.App/containerApps"
    metric_name      = "ResponseTime"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 500
  }

  action {
    action_group_id = azurerm_monitor_action_group.operations.id
  }
}

resource "azurerm_consumption_budget_resource_group" "main" {
  name              = "budget-${local.prefix}"
  resource_group_id = azurerm_resource_group.main.id
  amount            = var.budget_amount
  time_grain        = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00'Z'", timestamp())
  }

  dynamic "notification" {
    for_each = toset([25, 50, 75, 90, 100])
    content {
      enabled        = true
      threshold      = notification.value
      operator       = "GreaterThanOrEqualTo"
      threshold_type = "Actual"
      contact_emails = var.budget_contact_emails
      contact_groups = [azurerm_monitor_action_group.operations.id]
    }
  }

  lifecycle {
    ignore_changes = [time_period[0].start_date]
  }
}

