variable "unique_suffix" { type = string }
variable "image_tag" { type = string }
variable "database_admin_password" {
  type      = string
  sensitive = true
}
variable "payload_encryption_key" {
  type      = string
  sensitive = true
}
variable "github_repository" { type = string }
variable "budget_contact_emails" {
  type      = list(string)
  sensitive = true
}
variable "alert_action_group_email" {
  type      = string
  sensitive = true
}
variable "postgresql_allowed_ips" {
  type    = map(object({ start_ip = string, end_ip = string }))
  default = {}
}
variable "location" {
  type    = string
  default = "centralindia"
}
variable "budget_amount" {
  type    = number
  default = 250
}
variable "public_url" {
  type     = string
  default  = null
  nullable = true
}
variable "web_url" {
  type     = string
  default  = null
  nullable = true
}
variable "cors_origins" {
  type    = list(string)
  default = []
}
