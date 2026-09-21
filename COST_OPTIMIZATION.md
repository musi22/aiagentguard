# Azure cost optimization

AgentGuard has two explicit modes. Exactly one Terraform flag is true, so an
ambiguous mixed deployment fails at plan time.

| Cost area | Startup (`dev`, `staging`) | Production (`prod`) |
| --- | --- | --- |
| Dashboard | Static Web Apps Free | Static Web Apps Standard behind Front Door |
| API/gateway | Container Apps consumption, min 0, max 2 | min 2, autoscaling limits configurable |
| Worker | one-minute scheduled Container Apps Job | same schedule; no idle replica |
| PostgreSQL | burstable B1ms, 32 GiB, 7-day backup | General Purpose, zone HA, 128 GiB, 35-day backup |
| Registry | ACR Basic | ACR Premium |
| Redis | not deployed | Azure Managed Redis Balanced B0 |
| Edge/WAF | not deployed | Front Door Premium and prevention-mode WAF |
| Audit blobs | LRS; cool at 7 days, archive at 30, delete at 90 | ZRS; cool 30, archive 90, delete after 7 years |
| Logs | 0.5 GiB/day cap, 30 days | 10 GiB/day cap, 90 days |
| Networking | public service endpoints; DB exact-IP allowlist | VNet and private endpoints |

These are design choices, not a price quote. Azure prices and free grants vary by
agreement, region, currency, and date. Neither PostgreSQL Flexible Server nor ACR
should be assumed free. Use the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/)
with the actual region before applying.

## Guardrails already implemented

- Every resource is tagged with project, environment, owner, cost center, mode,
  repository, and Terraform ownership.
- Resource-group budgets alert at 25, 50, 75, 90, and 100 percent.
- Startup HTTP replicas scale to zero; the worker uses scheduled execution so
  background work does not disappear when an HTTP app scales down.
- Managed Redis, Front Door/WAF, Premium ACR, HA database, ZRS storage, and private
  endpoints are production-only.
- Log ingestion is capped and retention is explicit.
- Image tags are immutable SHAs and ACR admin credentials are disabled.

Budgets alert; they do not stop spending. Pair them with Azure Cost Management
anomaly alerts, a monthly owner review, and quota limits. Never automate resource
shutdown solely from a budget webhook without a tested exception path—doing so
could stop authorization and cause high-risk tools to fail unpredictably.

## Lowest-cost safe starting point

1. Deploy only `dev`.
2. Leave `postgresql_allowed_ips` empty unless a human or CI migration client
   genuinely needs direct access. Container Apps access needs a deliberate secure
   path; do not open `0.0.0.0`.
3. Keep Managed Redis disabled while a single database-backed correctness path is
   sufficient. Never use per-process counters for security decisions across
   multiple replicas.
4. Keep Front Door disabled until the public launch needs centralized WAF/custom
   domains.
5. Retain only sanitized audit payloads in PostgreSQL; export immutable records to
   Blob and lifecycle them to cool/archive tiers.
6. Inspect actual Log Analytics ingestion weekly. Sampling must never discard
   authorization decisions or security audit events.

## Scaling triggers

Enable production architecture when any of these become true:

- more than one online replica needs distributed locks/counters;
- contractual availability requires two replicas and zone-redundant database HA;
- sensitive data policy requires private endpoints;
- external launch requires edge WAF and bot protection;
- observed CPU, concurrency, or database saturation reaches 70 percent during a
  sustained peak;
- recovery objectives require longer PITR and durable audit retention.

Scale from measurements. Container Apps concurrency settings are initial values,
not promises of 1,000 requests/sec. Run the load suite against a disposable
environment and adjust replicas, CPU/memory, PostgreSQL SKU, connection pooling,
and indexes from p50/p95/p99 evidence.

## Routine FinOps review

- Daily: anomaly alerts and unexpected resource creation.
- Weekly: Container Apps vCPU/GiB-seconds, log ingestion, database CPU/connections,
  blob growth, and Redis utilization.
- Monthly: budget forecast, idle staging resources, reserved-capacity eligibility,
  orphaned private endpoints/IPs, and restore-test storage.
- Quarterly: retest mode assumptions and current Azure SKUs/prices.

The official references to check at each review are [Container Apps pricing](https://azure.microsoft.com/pricing/details/container-apps/),
[PostgreSQL pricing](https://azure.microsoft.com/pricing/details/postgresql/flexible-server/),
[Azure Managed Redis pricing](https://azure.microsoft.com/pricing/details/managed-redis/),
[Front Door pricing](https://azure.microsoft.com/pricing/details/frontdoor/), and
[Static Web Apps plans](https://learn.microsoft.com/azure/static-web-apps/plans).

