# AgentGuard Azure Terraform

The `modules/platform` module implements both cost-conscious startup mode and
HA production mode. The modes are mutually exclusive and guarded by Terraform
preconditions. `environments/dev`, `staging`, and `prod` are independent state
roots so a bad development apply cannot modify production.

Before the first deployment, run `bootstrap` once as an Azure identity allowed
to create Entra applications and subscription role assignments. Its outputs are
GitHub configuration values, not secrets. It creates federated credentials for
the `dev`, `staging`, and `production` GitHub environments; no client secret is
created.

Use Azure Blob remote state with Microsoft Entra authentication. Copy each
`backend.hcl.example` to the ignored `backend.hcl` and create the state account
once using your platform bootstrap process. Copy `terraform.tfvars.example` to
the ignored `terraform.tfvars`; inject database and encryption keys using
`TF_VAR_database_admin_password` and `TF_VAR_payload_encryption_key`.

```sh
terraform -chdir=infra/terraform/environments/dev init -backend-config=backend.hcl
terraform -chdir=infra/terraform/environments/dev validate
terraform -chdir=infra/terraform/environments/dev plan -var-file=terraform.tfvars
```

Never use a `0.0.0.0` PostgreSQL firewall rule. Startup databases accept only
explicit `start_ip`/`end_ip` pairs. Production PostgreSQL, Key Vault, Blob, and
Azure Managed Redis use the VNet/private endpoint path. Production also enables
Front Door Premium with WAF and sets API/gateway minimum replicas to two.

Azure Managed Redis uses `Microsoft.Cache/redisEnterprise@2025-07-01` via the
AzAPI provider, not the retiring Azure Cache for Redis resource. The scheduled
worker is a Container Apps Job on a one-minute UTC cron, preventing a scale-to-
zero background worker from silently ceasing work.
