# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS python-base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/home/agentguard/.local/bin:${PATH}"
WORKDIR /workspace
RUN groupadd --system --gid 10001 agentguard \
    && useradd --system --uid 10001 --gid agentguard --create-home agentguard
COPY packages ./packages
COPY apps ./apps
COPY cli ./cli
COPY integrations ./integrations
COPY scripts ./scripts
COPY migrations ./migrations
COPY pyproject.toml README.md* alembic.ini ./
RUN pip install --no-cache-dir \
      ./packages/shared-types \
      ./packages/policy-engine \
      ./packages/risk-engine \
      . \
    && chown -R agentguard:agentguard /workspace
USER agentguard

FROM python-base AS api
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["uvicorn", "agentguard_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python-base AS gateway
EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=2)"
CMD ["uvicorn", "agentguard_gateway.main:app", "--host", "0.0.0.0", "--port", "8001"]

FROM python-base AS worker
CMD ["python", "-m", "agentguard_worker.main"]

FROM node:22-alpine AS web-builder
WORKDIR /workspace/apps/web
COPY apps/web/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY apps/web ./
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_GATEWAY_URL=http://localhost:8001
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_GATEWAY_URL=${NEXT_PUBLIC_GATEWAY_URL} \
    NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM nginx:1.27-alpine AS web
COPY --from=web-builder /workspace/apps/web/out /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/
