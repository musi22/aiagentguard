module "agentguard" {
  source = "../../modules/platform"

  environment              = "prod"
  location                 = var.location
  unique_suffix            = var.unique_suffix
  startup_mode             = false
  production_mode          = true
  image_tag                = var.image_tag
  database_admin_password  = var.database_admin_password
  payload_encryption_key   = var.payload_encryption_key
  postgresql_allowed_ips   = {}
  github_repository        = var.github_repository
  budget_amount            = var.budget_amount
  budget_contact_emails    = var.budget_contact_emails
  alert_action_group_email = var.alert_action_group_email
  cors_origins             = var.cors_origins
  public_url               = var.public_url
  web_url                  = var.web_url
  front_door_enabled       = true
  managed_redis_enabled    = true
  api_max_replicas         = 20
  gateway_max_replicas     = 40
  log_retention_days       = 90
}
