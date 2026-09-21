# Disaster recovery

This runbook treats authorization correctness and audit evidence as the critical
assets. An outage must not grant authority. Gateway and API failures therefore
fail closed for production/high-risk actions.

## Recovery objectives

Set contractual RTO/RPO after measuring restores. Initial engineering targets:

| Component | Target RPO | Target RTO | Recovery source |
| --- | ---: | ---: | --- |
| PostgreSQL production | <= 5 minutes | <= 60 minutes | Flexible Server PITR/geo backup strategy |
| Audit archive | <= 15 minutes | <= 4 hours | versioned ZRS Blob plus lifecycle archive |
| API/gateway/worker | 0 | <= 30 minutes | immutable ACR SHA and Terraform |
| Policies/config | database RPO | database RTO | PostgreSQL restore |
| Key Vault secrets | documented rotation state | <= 60 minutes | soft delete/purge protection plus reissue |
| Static dashboard | 0 | <= 30 minutes | source SHA and CI build |

Terraform currently enables local zone redundancy, PITR retention, Blob versions,
Key Vault soft delete/purge protection, and immutable image tags. It does not
claim multi-region failover. Add a paired-region module, replicated secrets, GRS/
GZRS audit storage, database geo-backup/read replica, and Front Door priority
origins before promising regional disaster recovery.

## Incident decision flow

1. Declare the incident, record UTC time, severity, tenant scope, and commander.
2. If authorization integrity is uncertain, activate the global production kill
   switch. Do not bypass AgentGuard to restore a protected tool.
3. Preserve logs, correlation IDs, revision names, image digests, database server
   identity, and Terraform state versions.
4. Determine whether failure is application, dependency, data corruption,
   credential compromise, or regional Azure failure.
5. Prefer service/revision rollback when data is healthy. Restore data to a new
   server when corruption or destructive migration is suspected.
6. Validate tenant isolation and decision/audit consistency before traffic.
7. Communicate status without including secrets or sensitive request payloads.

## Application rollback

Container Apps keeps multiple revisions. Find the last known-good immutable SHA,
shift traffic only after checking it is compatible with the current schema, and
leave the failed revision available for forensics:

```sh
az containerapp revision list --resource-group <rg> --name <app> -o table
az containerapp ingress traffic set --resource-group <rg> --name <app> \
  --revision-weight <known-good-revision>=100
```

Rollback API and gateway together when their contract changed. Do not point to
`latest`. Pause the scheduled worker if it could make corruption worse:

```sh
az containerapp job stop --resource-group <rg> --name <worker-job>
```

## PostgreSQL restore

Never restore over the source server. Create a new server at the selected point
before the incident or migration, validate it privately, then update controlled
configuration and redeploy:

```sh
az postgres flexible-server restore \
  --resource-group <rg> \
  --name <new-server-name> \
  --source-server <source-server-id> \
  --restore-time "<UTC-RFC3339>"
```

Validate row counts, foreign keys, tenant scoping, policy versions, pending
approvals, budgets, credential revocation state, and the audit hash chain. Expire
all approvals that crossed the restore boundary; they may otherwise replay state
that no longer exists. Rotate database credentials and update `database-password`
after a suspected compromise.

Record the restored server in Terraform before the next normal apply. A manual
resource not imported or represented in configuration can be destroyed or
replaced accidentally.

## Audit archive recovery

Blob versioning protects overwrites/deletes within retention. Restore selected
versions to a new prefix/container, verify hashes and ordering, then reconcile
PostgreSQL audit rows. Do not rewrite original archived objects during evidence
collection. Legal-hold/immutability policies are organization-specific and must
be configured before claiming WORM compliance.

## Key Vault recovery and compromise

For accidental deletion, recover the soft-deleted vault or secret. For compromise,
recovery alone is insufficient:

1. disable the affected integration/agent;
2. revoke the credential at its issuer;
3. create a replacement secret version;
4. restart/refresh clients without logging the value;
5. invalidate active sessions/API keys where relevant;
6. search sanitized audit metadata for unauthorized use.

Production purge protection means a deleted name cannot be immediately reused;
account for this during regional naming and restoration.

## Terraform state recovery

Remote state versioning is mandatory. Copy the suspected state version for
forensics, restore the last valid version, run `terraform plan -refresh-only`,
and inspect every proposed change. Never use `terraform state rm`, force-unlock,
or `apply -refresh=false` as an unreviewed incident shortcut.

## Validation before reopening traffic

- `/health` and `/ready` succeed from the intended network path.
- PostgreSQL TLS/private DNS and Managed Redis TLS/Entra authentication work.
- Allow, deny, approval, expiry, budget, rate limit, and kill switch tests pass.
- Slack/webhook signatures and replay prevention pass.
- A decision and tool result create one correlated, tamper-evident audit chain.
- Cross-tenant/IDOR security tests pass.
- Worker processes expiration, delivery retry, aggregation, and archive jobs once.
- Alerts reach the on-call action group.
- Front Door WAF is in prevention mode and origins do not expose an unintended
  bypass path.

The incident commander—not an automated script—authorizes reopening. Keep the
kill switch active until high-risk flow validation is complete.

## Exercises

- Monthly: restore a representative database to an isolated server and measure
  RPO/RTO.
- Quarterly: roll back API/gateway revisions, recover a Blob version, and rotate
  a Key Vault secret.
- Semiannually: simulate region loss and rebuild from Terraform/state/source in a
  paired region.
- After every exercise: record timings, gaps, owners, and due dates; update these
  targets from evidence.

Useful Microsoft guidance: [PostgreSQL backup and restore](https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-backup-restore),
[Key Vault recovery management](https://learn.microsoft.com/azure/key-vault/general/key-vault-recovery),
and [Blob versioning](https://learn.microsoft.com/azure/storage/blobs/versioning-overview).
