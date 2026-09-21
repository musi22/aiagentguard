# Architecture

AgentGuard uses a stateless Next.js/FastAPI edge with PostgreSQL as authoritative state. Redis is used only for distributed rate counters, Key Vault for secret material, Blob Storage for long-term immutable audit artifacts, and Container Apps Jobs for bounded background work.

The web dashboard talks to the control-plane API with HttpOnly opaque-session cookies and CSRF tokens. Agents use hashed scoped bearer credentials through the gateway or API. `authorize` freezes an encrypted execution envelope. Remote connectors execute only after a database compare-and-set; local tools receive one-use claims. The worker handles notifications, expiry, delivery retries, reconciliation-preserving budget state, and retention.

PostgreSQL RLS is defense in depth. API sessions set `app.current_organization` on every transaction; all application queries still include organization predicates. The worker has a separate audited managed identity for global discovery and always scopes mutations per tenant. The migration identity owns schema; API and worker identities receive only required grants.

See `FEATURES.md` for feature paths, `THREAT_MODEL.md` for trust boundaries, and `AZURE_DEPLOYMENT.md` for topology and rollout.
