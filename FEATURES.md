# AgentGuard feature guide

The platform has two planes. The **control plane** is the dashboard/API used to register agents, tools, people, policy and integrations. The **runtime plane** is `/authorize`, `/execute`, request polling, and one-use SDK execution claims. A tool must never run unless the runtime plane returns an executable state.

## Requested product features

| Feature | What it does | Where to use or verify it |
|---|---|---|
| Authentication | Password login with Argon2, rotating opaque sessions, lockout, magic links, and Microsoft/Google/GitHub OAuth with state and PKCE. | Dashboard sign-in; `/api/v1/auth/*`; `tests/security/test_auth_security.py` |
| RBAC | Owner/admin manage configuration, approvers decide requests, auditors/viewers read; API keys carry explicit read/write/admin scopes. | `dependencies.py`, guarded admin routes |
| Organizations | Every business row carries an organization ID; PostgreSQL RLS adds a database isolation boundary. | Settings, migration `0002_tenant_rls` |
| Workspaces | Separates environments or business units and scopes agents and policies. | Team page and `/workspaces` |
| Teams | Groups members and agents inside a workspace for ownership and policy facts. | Team page and `/teams` |
| Invitations | Owners/admins invite an email with a bounded role; a random hashed token is consumed once. | Team page and `/invitations` |
| Agents | Registers framework, model provider, environment, team and lifecycle status. Suspending/revoking stops new and pending execution. | Agents page and `/agents` |
| Agent credentials | Random machine keys are shown once, stored only as a peppered hash, scoped to environment/tools, expirable, rotatable, and revocable. | Agents/API keys pages; `/agents/{id}/credentials` |
| Tool catalog | Defines provider, schemas, risk metadata, tags and adapter. HTTPS/MCP destinations are SSRF checked and no redirect is followed. | Tools page and `/tools` |
| Agent-to-tool permissions | Optional mapping can deny a specific agent/tool pair in addition to credential scope. | `agent_tool_permissions` and authorization engine |
| Policy engine | Deterministic priority evaluation with deny by default and allow/deny/approval obligations. Versioned JSON or YAML is validated before publication. | Policies page, `packages/policy-engine` |
| Policy simulation | Evaluates a candidate document and facts without changing live enforcement. | Policies → Simulate; `/policies/simulate` |
| Risk engine | Produces a bounded 0–100 score plus human-readable factors from tool, environment and history. | Risk and request views; `packages/risk-engine` |
| Human approval | Freezes sanitized arguments, policy version and tool configuration digest; any eligible approver can approve/reject before TTL. | Approvals page; Slack action webhook |
| Budgets | Reserves minor currency units atomically before execution for per-action/daily/weekly/monthly scoped limits, then spends or releases once. Unknown provider outcomes remain reserved. | Budgets page; `/budgets` |
| Rate limits | Fixed-window organization/workspace/agent/tool limits; Redis uses atomic Lua in production and fails closed if the distributed counter is unavailable. | Budgets page; `/rate-limits` |
| Kill switches | Organization/workspace/team/agent/tool/environment emergency stops are checked at authorization and again immediately before execution. | Settings; `/kill-switch` |
| DLP | Recursively detects common secrets/PII plus bounded custom regexes; organization action can allow, warn, redact, require approval or block. | Settings; `packages/shared-types` |
| Runtime `/authorize` | Authenticates a machine credential, validates schema, computes trusted facts/risk/policy/DLP/limits, freezes payload and returns an explicit decision. | SDKs, gateway, integration tests |
| Runtime `/execute` | For remote adapters only, performs a compare-and-set before exactly one provider call; repeated idempotency returns the stored request and never retries the side effect. | Gateway and `/execute` |
| SDK execution claims | For local SDK tools, a one-use short-lived claim returns frozen arguments; the result requires the claim token and consumes it once. | Python/TypeScript `protect` decorators |
| Integrations | Real Stripe refund, GitHub read/branch/merge/delete, parameterized PostgreSQL, generic HTTPS and MCP adapters; secrets resolve only from Key Vault/local environment references. | Integrations/Tools pages; `connectors.py` |
| Notifications and webhooks | Worker sends Slack approval blocks/email webhooks and signed outbound events with bounded exponential retry. Slack callbacks verify timestamp and HMAC. | Worker, `/webhooks/slack/actions` |
| Audit trail | Stores decision/execution metadata, hashes rather than raw arguments, DLP-sanitizes values and links each event cryptographically. JSON/CSV export and chain verification are built in. | Audit page; `/audit/export`, `/audit/verify` |
| Retention/archive | Worker moves old events to private versioned Blob Storage and writes an audit checkpoint so the remaining chain stays verifiable. | Worker archive job and lifecycle policy |
| Analytics | Server-side overview, decision/risk/spend/activity aggregates rendered without invented placeholder data. | Overview/Analytics dashboard |
| Billing | Plan quotas are enforced server-side; Stripe Checkout and customer portal use real redirects when configured. | Billing page; `/billing/*` |
| Python SDK | Sync/async client, polling with timeout, fail-closed behavior, frozen-argument decorator, explicit no unsafe retries. | `packages/sdk-python` |
| TypeScript SDK | Equivalent authorize/execute/wait/claim/result lifecycle for Node applications. | `packages/sdk-typescript` |
| CLI | Lists resources, authorizes/executes, follows approvals, and inspects/export/verifies audit data. | `cli/agentguard_cli` |
| Gateway | Small independently scalable proxy; forwards runtime calls and fails closed on upstream failure. | `apps/gateway` |
| Dashboard | Responsive operational UI with real loading, empty/error states, CRUD forms, charts only when data exists, and an embedded feature guide. | `apps/web` |
| Azure deployment | Static Web Apps, Container Apps, Jobs, PostgreSQL, Managed Redis, Key Vault, Blob audit archive, ACR, Log Analytics/App Insights; prod adds private networking, Front Door Premium/WAF and HA. | `infra/terraform`, `AZURE_DEPLOYMENT.md` |
| CI/CD | Lint/type/test/build/scan; OIDC to Azure; immutable SHA images; migration job before rollout; protected production environment. | `.github/workflows` |

## Safe execution sequence

1. The agent SDK submits a tool name, arguments, context and idempotency key.
2. AgentGuard validates the machine identity, current tenant, tool scope, JSON schema and current kill state.
3. DLP, risk and policy run on trusted server-side metadata; budgets reserve and rate counters increment only for potentially executable decisions.
4. A deny returns immediately. An approval freezes the sanitized payload and waits for a human. An allow becomes short-lived authorization.
5. Immediately before execution AgentGuard rechecks organization, agent, credential, tool, permission and kill state, plus the frozen tool configuration digest.
6. Remote adapters are compare-and-set to `executing` before the provider call. SDK adapters use one-time claims. The sanitized outcome and budget settlement are audited.

Examples are in `examples/langgraph_refund_agent.py` and `examples/coding_agent.py`.
