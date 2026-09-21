module "agentguard" {
  source = "../../modules/platform"

  environment              = "dev"
  location                 = var.location
  unique_suffix            = var.unique_suffix
  startup_mode             = true
  production_mode          = false
  image_tag                = var.image_tag
  database_admin_password  = var.database_admin_password
  payload_encryption_key   = var.payload_encryption_key
  postgresql_allowed_ips   = var.postgresql_allowed_ips
  github_repository        = var.github_repository
  budget_amount            = var.budget_amount
  budget_contact_emails    = var.budget_contact_emails
  alert_action_group_email = var.alert_action_group_email
  cors_origins             = var.cors_origins
  public_url               = var.public_url
  web_url                  = var.web_url
  front_door_enabled       = false
  managed_redis_enabled    = false
}
