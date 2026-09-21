# Operations runbook

## Triage

1. Identify environment, tenant, correlation/request ID and first failing timestamp; never paste secrets.
2. Check `/health`, `/ready`, Container Apps revision health, PostgreSQL, Redis, worker job executions and the correlated audit chain.
3. If unauthorized or dangerous execution is possible, activate the narrowest kill switch; revoke the agent credential and affected integration secret.
4. Preserve audit exports, deployment SHA and provider request IDs before remediation.

## Common incidents

- **API unhealthy:** stop rollout, inspect App Insights exceptions/dependencies, confirm Entra DB token and Key Vault access, then restore the last compatible immutable image.
- **Rate service unavailable:** execution with matching limits intentionally fails closed; restore Redis identity/networking, do not bypass enforcement.
- **Approval backlog:** confirm worker schedule and Slack/email integration. Expired approvals remain denied; never manually change request status.
- **Unknown provider outcome:** leave budget reserved, query the provider by idempotency/reference, then reconcile through an audited operator procedure.
- **Suspected tenant leak:** organization kill, revoke sessions/keys, isolate revision, verify RLS role/grants, export both tenant audit chains and notify security/legal.
- **Audit verification failure:** stop retention, preserve database/blob versions, compare checkpoint/archive manifest and investigate database/storage activity logs.

Recovery and restore drills are in `DISASTER_RECOVERY.md`; rollout commands are in `AZURE_DEPLOYMENT.md`.
