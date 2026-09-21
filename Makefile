SHELL := /bin/sh
ENV ?= dev
TF_DIR := infra/terraform/environments/$(ENV)
IMAGE_TAG ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo local)

.PHONY: setup test dev build down terraform-init terraform-fmt terraform-validate terraform-plan terraform-apply deploy-dev deploy-staging deploy-prod

setup:
	@test -f .env || cp .env.example .env
	@echo "Created .env when absent. Set POSTGRES_PASSWORD and a Fernet PAYLOAD_ENCRYPTION_KEY before starting."

test:
	python -m pytest
	cd apps/web && npm test --if-present

dev:
	docker compose up --build

build:
	docker build --target api -t agentguard-api:$(IMAGE_TAG) .
	docker build --target gateway -t agentguard-gateway:$(IMAGE_TAG) .
	docker build --target worker -t agentguard-worker:$(IMAGE_TAG) .
	docker build --target web -t agentguard-web:$(IMAGE_TAG) .

down:
	docker compose down

terraform-init:
	terraform -chdir=$(TF_DIR) init -backend-config=backend.hcl

terraform-fmt:
	terraform fmt -recursive infra/terraform

terraform-validate: terraform-init
	terraform -chdir=$(TF_DIR) validate

terraform-plan: terraform-init
	terraform -chdir=$(TF_DIR) plan -var-file=terraform.tfvars -out=tfplan

terraform-apply: terraform-init
	terraform -chdir=$(TF_DIR) apply tfplan

deploy-dev:
	./scripts/deploy.sh dev $(IMAGE_TAG)

deploy-staging:
	./scripts/deploy.sh staging $(IMAGE_TAG)

deploy-prod:
	@test "$(IMAGE_TAG)" != "local" || (echo "Production requires immutable IMAGE_TAG" && exit 1)
	./scripts/deploy.sh prod $(IMAGE_TAG)

