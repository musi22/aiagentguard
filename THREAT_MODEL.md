# Threat model

Protected assets are tenant data, provider credentials, execution authority, approval integrity, budget capacity, billing state and audit evidence. Trust boundaries exist between browser/API, agent/gateway, API/providers, API/database/Redis/Key Vault, worker/integrations, and Azure/GitHub deployment identities.

Principal threats and controls:

- **Cross-tenant access:** organization predicates, database RLS, tenant-bound credentials/sessions and isolation tests.
- **Agent or key compromise:** narrow scopes, expiry/revocation, environment binding, kill switches and pre-execution recheck.
- **Approval replay/TOCTOU:** encrypted frozen payload, policy/tool digest, TTL, locked decision, one-use execution claim.
- **Duplicate financial/destructive action:** credential-bound idempotency, durable compare-and-set and no unsafe retry.
- **SSRF/secret exfiltration:** HTTPS and allowlists, DNS/IP checks, no redirects/inline secrets, DLP sanitization.
- **Budget races:** PostgreSQL advisory/row locks or atomic Redis counters and reservation settlement exactly once.
- **Audit alteration:** per-tenant serialized hash chain, private/versioned archive and checkpoint verification.
- **Supply-chain/deployment abuse:** pinned ranges/lock files, CI scanning, GitHub OIDC, protected production approval, immutable SHA images.

Residual risks include a fully compromised Azure subscription, malicious database owner, provider-side non-idempotence after a lost response, regex false positives, and external provider semantics changing. Mitigate with Azure activity logs/PIM, separation of duties, provider reconciliation, tuned DLP patterns and contract tests.
