# Contributing

Use small changes with tests at the layer affected. Preserve tenant predicates and fail-closed behavior. Any execution-path change needs allow, deny, approval, expiry, replay, credential-scope, kill-switch and error-path coverage. Never add a retry around a side effect without a provider-enforced idempotency contract.

Run Python lint, type checks and tests plus web typecheck/build before review. Run `terraform fmt -recursive -check` and `terraform validate` in every environment when the host trust store permits provider startup. Document migrations as expand/migrate/contract and include rollback/recovery impact.
