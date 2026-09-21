# Security

Never place provider tokens, database passwords, webhook secrets, encryption keys, or generated AgentGuard credentials in source, Terraform variables committed to Git, tool config, logs, screenshots, or issue reports. Production reads them by managed identity from Azure Key Vault. Agent/admin keys are displayed once and stored as peppered hashes.

The runtime is fail closed: timeout, invalid JSON/schema, unavailable Redis when limits exist, missing identity, unknown policy, expired approval, changed tool config, or emergency disable prevents execution. Side-effecting calls have no automatic retry. Financial tools require a finite nonnegative amount; an uncertain remote provider outcome retains reserved budget pending reconciliation.

Connector URLs must be HTTPS, match an explicit host allowlist, resolve only to public addresses, contain no embedded credentials, and cannot redirect. PostgreSQL tools execute registered parameterized statements only. DLP-sanitized data—not raw tool content—is written to audit or notifications.

Report vulnerabilities privately to the repository owner with reproduction, impact and affected revision. Do not include live customer data or credentials. Rotate exposed values, revoke affected sessions/keys, activate a relevant kill switch, preserve audit evidence, and follow `RUNBOOK.md`.
