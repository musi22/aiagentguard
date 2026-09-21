resource "azurerm_cdn_frontdoor_profile" "main" {
  count                    = var.front_door_enabled ? 1 : 0
  name                     = "afd-${local.prefix}-${local.suffix}"
  resource_group_name      = azurerm_resource_group.main.name
  sku_name                 = "Premium_AzureFrontDoor"
  response_timeout_seconds = 60
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "endpoint" {
  for_each = var.front_door_enabled ? toset(["dashboard", "api", "gateway"]) : []

  name                     = "${local.prefix}-${each.key}-${local.suffix}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id
  enabled                  = true
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "origin" {
  for_each = var.front_door_enabled ? toset(["dashboard", "api", "gateway"]) : []

  name                     = "${each.key}-origins"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id
  session_affinity_enabled = false

  health_probe {
    interval_in_seconds = 60
    path                = each.key == "dashboard" ? "/" : "/health"
    protocol            = "Https"
    request_type        = "GET"
  }

  load_balancing {
    additional_latency_in_milliseconds = 50
    sample_size                        = 4
    successful_samples_required        = 3
  }
}

locals {
  frontdoor_origins = {
    dashboard = azurerm_static_web_app.dashboard.default_host_name
    api       = azurerm_container_app.api.ingress[0].fqdn
    gateway   = azurerm_container_app.gateway.ingress[0].fqdn
  }
}

resource "azurerm_cdn_frontdoor_origin" "origin" {
  for_each = var.front_door_enabled ? local.frontdoor_origins : {}

  name                           = each.key
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.origin[each.key].id
  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = each.value
  origin_host_header             = each.value
  http_port                      = 80
  https_port                     = 443
  priority                       = 1
  weight                         = 1000

  dynamic "private_link" {
    for_each = each.key == "dashboard" ? [] : [1]
    content {
      request_message        = "AgentGuard Front Door private origin"
      target_type            = "managedEnvironments"
      location               = azurerm_container_app_environment.main.location
      private_link_target_id = azurerm_container_app_environment.main.id
    }
  }
}

resource "azurerm_cdn_frontdoor_route" "route" {
  for_each = var.front_door_enabled ? toset(["dashboard", "api", "gateway"]) : []

  name                          = "${each.key}-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.endpoint[each.key].id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.origin[each.key].id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.origin[each.key].id]
  enabled                       = true
  forwarding_protocol           = "HttpsOnly"
  https_redirect_enabled        = true
  patterns_to_match             = ["/*"]
  supported_protocols           = ["Http", "Https"]
  link_to_default_domain        = true
}

resource "azurerm_cdn_frontdoor_firewall_policy" "main" {
  count               = var.front_door_enabled ? 1 : 0
  name                = "waf${var.environment}${local.suffix}"
  resource_group_name = azurerm_resource_group.main.name
  sku_name            = azurerm_cdn_frontdoor_profile.main[0].sku_name
  enabled             = true
  mode                = "Prevention"
  tags                = local.tags

  managed_rule {
    type    = "DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.1"
    action  = "Block"
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "main" {
  count                    = var.front_door_enabled ? 1 : 0
  name                     = "agentguard-waf"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.main[0].id

      association {
        patterns_to_match = ["/*"]
        dynamic "domain" {
          for_each = azurerm_cdn_frontdoor_endpoint.endpoint
          content {
            cdn_frontdoor_domain_id = domain.value.id
          }
        }
      }
    }
  }
}
