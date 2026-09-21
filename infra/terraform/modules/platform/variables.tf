variable "environment" {
  description = "Deployment environment."
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod."
  }
}

variable "location" {
  type    = string
  default = "centralindia"
}

variable "unique_suffix" {
  description = "Stable lowercase alphanumeric suffix (3-8 characters) used by globally unique resources."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,8}$", var.unique_suffix))
    error_message = "unique_suffix must contain 3-8 lowercase letters or digits."
  }
}

variable "startup_mode" {
  description = "Low-cost mode. Exactly one of startup_mode and production_mode must be true."
  type        = bool
}

variable "production_mode" {
  description = "HA/private-network mode. Exactly one of startup_mode and production_mode must be true."
  type        = bool
}

variable "image_tag" {
  description = "Immutable git SHA or release tag for all service images."
  type        = string
  validation {
    condition     = length(trimspace(var.image_tag)) > 0 && (!var.production_mode || lower(var.image_tag) != "latest")
    error_message = "image_tag is required and production may not use latest."
  }
}

variable "database_admin_username" {
  type    = string
  default = "agentguard_admin"
}

variable "database_admin_password" {
  description = "PostgreSQL password. Supply from a protected CI variable; Terraform state must be encrypted and access-restricted."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.database_admin_password) >= 16
    error_message = "database_admin_password must be at least 16 characters."
  }
}

variable "payload_encryption_key" {
  description = "URL-safe base64 Fernet key. Supply from a protected CI variable."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{43}=$", var.payload_encryption_key))
    error_message = "payload_encryption_key must be a valid 44-character Fernet key."
  }
}

variable "postgresql_allowed_ips" {
  description = "Startup-only explicit PostgreSQL firewall ranges. Never use 0.0.0.0 or the Azure-services sentinel rule."
  type = map(object({
    start_ip = string
    end_ip   = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for rule in values(var.postgresql_allowed_ips) :
      rule.start_ip != "0.0.0.0" && rule.end_ip != "0.0.0.0"
    ])
    error_message = "PostgreSQL firewall rules may not include 0.0.0.0."
  }
}

variable "github_repository" {
  description = "GitHub repository as owner/name for resource metadata."
  type        = string
}

variable "budget_amount" {
  type    = number
  default = 100
}

variable "budget_contact_emails" {
  type      = list(string)
  sensitive = true
}

variable "alert_action_group_email" {
  type      = string
  sensitive = true
}

variable "cors_origins" {
  type = list(string)
  default = []
}

variable "public_url" {
  description = "Public API URL used for OAuth/magic-link callbacks. Null uses the generated API or Front Door hostname."
  type        = string
  default     = null
  nullable    = true
}

variable "web_url" {
  description = "Dashboard URL used for redirects and cookie/CORS trust. Null uses Static Web Apps or Front Door."
  type        = string
  default     = null
  nullable    = true
}

variable "api_max_replicas" {
  type    = number
  default = 10
}

variable "gateway_max_replicas" {
  type    = number
  default = 20
}

variable "log_retention_days" {
  type    = number
  default = null
}

variable "front_door_enabled" {
  description = "Must remain enabled in production. May be disabled in startup mode."
  type        = bool
  default     = false
}

variable "managed_redis_enabled" {
  description = "Deploy Azure Managed Redis. Required in production."
  type        = bool
  default     = false
}

variable "front_door_custom_domains" {
  type    = map(string)
  default = {}
}

variable "static_web_app_sku" {
  type    = string
  default = null
}
