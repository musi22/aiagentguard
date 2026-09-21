# Integration adapters

The executable adapters live in `apps/api/agentguard_api/connectors.py` so every provider shares the same frozen-request, idempotency, audit, timeout, redaction, and SSRF controls. This directory documents provider-specific provisioning without duplicating security-sensitive execution code.

- `stripe.refund`: Stripe REST API, Key Vault secret reference, required idempotency key.
- GitHub: repository reads, branch creation, pull-request merge, and repository deletion through fixed operation handlers.
- Slack: signed interactive approval callbacks and worker-delivered Block Kit messages.
- PostgreSQL: administrator-defined parameterized statement; agents cannot submit raw SQL.
- Generic HTTP: fixed HTTPS endpoint, optional hostname allowlist, no redirects, private-address rejection.
- MCP: fixed server endpoint and fixed MCP tool name, JSON-RPC `tools/call` only.

Connector configuration stores only Key Vault secret names. Secret values never enter the database.
