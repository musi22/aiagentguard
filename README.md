# AgentGuard

AgentGuard is a tenant-isolated control plane and runtime gateway for AI-agent tool calls. It decides before execution, can require a person, enforces cost and request ceilings, keeps credentials out of agent code, and produces hash-linked audit evidence.

## Run locally

Prerequisites: Python 3.11+, Node 20+, and Docker Compose. Copy `.env.example` to `.env`, then use either:

```powershell
docker compose up --build
```

or run the services directly:

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -e ".[dev]"
.\.venv\Scripts\alembic upgrade head
$env:SEED_ADMIN_PASSWORD="choose-a-local-password"
.\.venv\Scripts\python scripts/seed.py
.\.venv\Scripts\uvicorn agentguard_api.main:app --reload --port 8000
```

In another terminal, run `npm install` and `npm run dev` from `apps/web`. Open `http://localhost:3000`; API docs are at `http://localhost:8000/docs` in development only.

## Repository map

- `apps/api`: control-plane and runtime API
- `apps/gateway`: independently scalable fail-closed runtime proxy
- `apps/worker`: approval notification, webhook, expiry, and audit archival jobs
- `apps/web`: responsive Next.js dashboard
- `packages`: deterministic policy, risk, DLP, and Python/TypeScript SDKs
- `cli`: administrative/runtime CLI
- `infra/terraform`: dev, staging, and production Azure infrastructure
- `tests`: unit, integration, security, load, and browser tests
- `FEATURES.md`: explanation and verification path for every requested feature

## Development checks

```powershell
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\ruff check .
.\.venv\Scripts\mypy apps packages cli
cd apps/web
npm run typecheck
npm run build
```

Read [SECURITY.md](SECURITY.md) before enabling connectors and [AZURE_DEPLOYMENT.md](AZURE_DEPLOYMENT.md) before provisioning billable resources.
