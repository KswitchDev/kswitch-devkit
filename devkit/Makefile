# KSwitch DevKit — operator Makefile
# ─────────────────────────────────────────
# All targets are self-contained. No target reaches outside this
# directory. The bundle is a runnable artefact distributed as a GitHub
# release tarball; the parent repository is not required at runtime.
#
# Free local DevKit — first-run + lifecycle targets.
#
# This Makefile is asserted in CI against:
#   - `make up` healthy in <5 min warm cache, <15 min cold
#   - `make up` self-seeds and self-smokes — no operator steps
#   - `make doctor` exits 0 when all-green, prints remediation hints
#   - DevKit docs served at https://localhost:5001/docs/
#   - Admin password file auto-deleted after first login
#   - Force-change-on-first-login (UPDATE_PASSWORD required action)
#   - Bundled-password time-bomb (valid_until +24h)
#   - `make seed` re-run does not reset admin password
#   - `make seed-reset` requires KSWITCH_CONFIRM_SEED_RESET=yes
#   - Self-signed cert generated without OS trust-store changes
#   - Bundle is self-contained (extract & run, no parent repo)

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# ─── Paths (relative to this bundle root, never to a parent repo) ────
BUNDLE_ROOT  := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SCRIPTS_DIR  := $(BUNDLE_ROOT)/scripts
STATE_DIR    := $(BUNDLE_ROOT)/state
TLS_DIR      := $(BUNDLE_ROOT)/tls
BACKUPS_DIR  := $(BUNDLE_ROOT)/backups
DIGESTS_LOCK := $(BUNDLE_ROOT)/image-digests.lock

# ─── Compose invocation ───────────────────────────────────────────────
# Honour DOCKER_HOST / DOCKER_CONTEXT for developers running rootless or
# remote daemons. The compose file enables the `identity` profile by
# default — KSwitch ships SPIRE as a first-class platform feature
# the bundle compose includes a self-bootstrapping spire-agent and the
# spire-agent socket mount the JWT materializers require.
COMPOSE      := docker compose
COMPOSE_FILE := -f $(BUNDLE_ROOT)/docker-compose.yml
# Default profiles (Tier B+ refined): identity brings up SPIRE + the
# five JWT materializers; gateway brings up the MCP gateway stack
# (envoy + gateway-opa + gateway-upstream). Observability lite
# (otel-collector + prometheus + grafana + tempo) is OFF by default —
# opt in with `make up-with-observability` or
# `docker compose --profile observability up -d`.
COMPOSE_PROFILES := --profile identity --profile gateway

# ─── Health-wait deadlines (G9) ───────────────────────────────────────
BOOT_DEADLINE_SECONDS := 300

# ─── Service URLs (used by `make next` / `make doctor`) ───────────────
APP_URL      := https://localhost:5001
DOCS_URL     := $(APP_URL)/docs/
KEYCLOAK_URL := http://localhost:3001

# ─── Runtime env propagated to scripts/ ──────────────────────────────
SCRIPT_ENV := \
  BUNDLE_ROOT=$(BUNDLE_ROOT) \
  STATE_DIR=$(STATE_DIR) \
  TLS_DIR=$(TLS_DIR) \
  BACKUPS_DIR=$(BACKUPS_DIR) \
  DIGESTS_LOCK=$(DIGESTS_LOCK) \
  APP_URL=$(APP_URL) \
  KEYCLOAK_URL=$(KEYCLOAK_URL) \
  COMPOSE_BIN="$(COMPOSE)" \
  COMPOSE_FILE_FLAG="$(COMPOSE_FILE)" \
  COMPOSE_PROFILES_FLAG="$(COMPOSE_PROFILES)"

.PHONY: help up up-with-observability mcp-install mcp-configs pull tls boot seed seed-reset smoke smoke-test next doctor down logs backup devkit-limits developer-limits licence-terms clean-state preflight

help: ## Show this help (the default target)
	@echo "KSwitch DevKit"
	@echo "========================="
	@echo ""
	@echo "First-time install:"
	@echo "  1. cp .env.example .env"
	@echo "  2. make up"
	@echo ""
	@echo "Hard local caps: 10 agents, 10 MCP servers, 100 tools, 100 skills"
	@echo "Licence: source-available, non-commercial; run 'make licence-terms'"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

# ─── Composite entry point (G9, G10) ──────────────────────────────────
up: preflight pull tls boot seed smoke next ## Composite: pull + tls + boot + seed + smoke + next

up-with-observability: COMPOSE_PROFILES := --profile identity --profile gateway --profile observability
up-with-observability: up ## Same as `make up` but also brings up otel-collector + prometheus + grafana + tempo. Grafana UI at http://localhost:3000 (default password GRAFANA_ADMIN_PASSWORD in .env).

mcp-install: ## Install bundled MCP commands for local developer tools
	@test -d $(BUNDLE_ROOT)/../mcp-server || { echo "FATAL: ../mcp-server not found"; exit 1; }
	python3 -m pip install -e $(BUNDLE_ROOT)/../mcp-server
	@echo "[mcp] installed kswitch-mcp, kswitch-proxy, kswitch-brain-mcp, kswitch-service-mcp"

mcp-configs: ## Show bundled MCP client config snippets
	@test -d $(BUNDLE_ROOT)/../mcp-server/configs || { echo "FATAL: ../mcp-server/configs not found"; exit 1; }
	@echo "Bundled config snippets:"
	@find $(BUNDLE_ROOT)/../mcp-server/configs -maxdepth 2 -type f | sort

# ─── Pre-flight: catch missing prerequisites before any work starts ──
preflight: ## Verify the host has docker compose, openssl, curl, jq
	@command -v docker >/dev/null 2>&1   || { echo "FATAL: docker not on PATH"; exit 1; }
	@$(COMPOSE) version >/dev/null 2>&1   || { echo "FATAL: docker compose plugin not installed"; exit 1; }
	@command -v openssl >/dev/null 2>&1  || { echo "FATAL: openssl not on PATH (needed for make tls)"; exit 1; }
	@command -v curl >/dev/null 2>&1     || { echo "FATAL: curl not on PATH (needed for make smoke / make doctor)"; exit 1; }
	@command -v jq >/dev/null 2>&1       || { echo "FATAL: jq not on PATH (needed for scripts/seed.sh)"; exit 1; }
	@test -f $(BUNDLE_ROOT)/.env || { echo "FATAL: $(BUNDLE_ROOT)/.env not found. cp .env.example .env"; exit 1; }
	@grep -qE '^KSWITCH_ACCEPT_DEVKIT_LICENSE=1$$' $(BUNDLE_ROOT)/.env || \
	  { echo "FATAL: DevKit Licence not accepted."; \
	    echo "       Read ../LICENSE.md, ../LICENSES/KSWITCH-DEVKIT-LICENSE.md, and ../COMMERCIAL-USE.md."; \
	    echo "       Then set KSWITCH_ACCEPT_DEVKIT_LICENSE=1 in $(BUNDLE_ROOT)/.env."; \
	    exit 1; \
	  }
	@grep -qE '^KSWITCH_CUSTOMER_ID=[a-z0-9-]+$$' $(BUNDLE_ROOT)/.env || \
	  { echo "FATAL: KSWITCH_CUSTOMER_ID missing or invalid in .env (lowercase letters / digits / hyphens)"; exit 1; }
	@grep -qE '^KEYCLOAK_ADMIN_PASSWORD=' $(BUNDLE_ROOT)/.env || \
	  { echo "FATAL: KEYCLOAK_ADMIN_PASSWORD missing in .env"; exit 1; }
	@if grep -qE '^KEYCLOAK_ADMIN_PASSWORD=CHANGE-ME-' $(BUNDLE_ROOT)/.env; then \
	  echo "FATAL: KEYCLOAK_ADMIN_PASSWORD in .env is still the placeholder."; \
	  echo "       Set a strong password (16+ chars, mixed case + digits)."; \
	  echo "       The placeholder is a known value and will be rejected."; \
	  exit 1; \
	fi
	@echo "[preflight] all good"

# ─── Image pull + digest snapshot (G23 — bundle-self-contained pin) ──
pull: ## Pull current minor-pinned images and snapshot digests to image-digests.lock
	$(COMPOSE) $(COMPOSE_FILE) $(COMPOSE_PROFILES) pull
	@printf '# Generated by `make pull` at %s\n# Image digests for the running DevKit stack.\n' "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" > $(DIGESTS_LOCK)
	@$(COMPOSE) $(COMPOSE_FILE) $(COMPOSE_PROFILES) config --images 2>/dev/null | sort -u | while read -r ref; do \
	  digest=$$(docker image inspect "$$ref" --format '{{index .RepoDigests 0}}' 2>/dev/null || echo ""); \
	  if [ -n "$$digest" ]; then echo "$$ref  $$digest" >> $(DIGESTS_LOCK); fi; \
	done
	@echo "[pull] image digests written to $(DIGESTS_LOCK)"

# ─── TLS — self-signed via openssl, no OS trust-store changes (G22) ──
tls: ## Generate ./tls/cert.pem + key.pem (no-op if cert.pem already exists)
	@$(SCRIPT_ENV) bash $(SCRIPTS_DIR)/tls.sh

# ─── Boot the stack and wait for healthy (G9) ────────────────────────
boot: ## docker compose up -d, wait for /api/v1/health/live on app within 5 min
	$(COMPOSE) $(COMPOSE_FILE) $(COMPOSE_PROFILES) up -d
	@echo "[boot] waiting up to $(BOOT_DEADLINE_SECONDS)s for app /api/v1/health/live..."
	@deadline=$$(( $$(date +%s) + $(BOOT_DEADLINE_SECONDS) )); \
	while [ $$(date +%s) -lt $$deadline ]; do \
	  if curl -sk $(APP_URL)/api/v1/health/live | grep -q '"status"' 2>/dev/null; then \
	    echo "[boot] app healthy"; \
	    exit 0; \
	  fi; \
	  sleep 5; \
	done; \
	echo "[boot] FATAL: app /healthz never became healthy within $(BOOT_DEADLINE_SECONDS)s"; \
	echo "[boot] hint: docker compose $(COMPOSE_FILE) logs --tail=200 app"; \
	exit 1

# ─── Seed Keycloak realm + admin user (idempotent, create-only on admin) ─
seed: ## Provision realm, policies, and admin user (G20a / G20b / G21)
	@$(SCRIPT_ENV) bash $(SCRIPTS_DIR)/seed.sh

# ─── Seed reset — destructive recovery, must be confirmed (G21a) ─────
seed-reset: ## Destroy admin user + regenerate credentials (set KSWITCH_CONFIRM_SEED_RESET=yes)
	@$(SCRIPT_ENV) bash $(SCRIPTS_DIR)/seed-reset.sh

# ─── Smoke probe — 10 representative endpoints, ~15s ─────────────────
smoke: ## Run the API smoke probe (no Playwright)
	@$(SCRIPT_ENV) bash $(SCRIPTS_DIR)/smoke.sh

# Alias surfaced as a developer-facing self-validation target.
smoke-test: smoke ## Alias of `make smoke`

# ─── Print operator next steps (G10) ─────────────────────────────────
next: ## Print admin URL + initial-admin credentials path (if file present)
	@echo ""
	@echo "✓ KSwitch is ready."
	@echo "  Admin sign-in:    $(APP_URL)/"
	@echo "  DevKit docs:      $(DOCS_URL)"
	@if [ -f $(STATE_DIR)/initial-admin.txt ]; then \
	  username=$$(grep '^KSWITCH_INITIAL_ADMIN_USERNAME=' $(STATE_DIR)/initial-admin.txt | cut -d= -f2-); \
	  echo "  Default admin:    $$username"; \
	  echo "                    Password (one-time, expires in 24h):"; \
	  echo "                      $(STATE_DIR)/initial-admin.txt   (mode 600)"; \
	  echo "                    Force-change on first login — you'll set your own"; \
	  echo "                    password before the session continues."; \
	  echo "                    Lost it? make seed-reset KSWITCH_CONFIRM_SEED_RESET=yes"; \
	else \
	  echo "  Default admin:    (initial-admin file already cleared — sign in with the password you set on first login)"; \
	fi
	@echo ""

# ─── Health probe + bundled-password time-bomb (G11, G20b) ───────────
doctor: ## Check service health + bundled-password expiry; PASS/WARN/FAIL with hints
	@$(SCRIPT_ENV) bash $(SCRIPTS_DIR)/doctor.sh

# ─── Tear-down + utility targets ─────────────────────────────────────
down: ## docker compose down (preserves volumes)
	$(COMPOSE) $(COMPOSE_FILE) $(COMPOSE_PROFILES) down

logs: ## Tail app + keycloak logs
	$(COMPOSE) $(COMPOSE_FILE) $(COMPOSE_PROFILES) logs -f --tail=100 app keycloak

backup: ## pg_dump postgres to ./backups/<timestamp>.sql.gz
	@mkdir -p $(BACKUPS_DIR)
	@ts=$$(date -u +%Y-%m-%dT%H-%M-%SZ); \
	out=$(BACKUPS_DIR)/kswitch-$$ts.sql.gz; \
	$(COMPOSE) $(COMPOSE_FILE) $(COMPOSE_PROFILES) exec -T postgres pg_dump -U postgres agent_register | gzip > $$out; \
	echo "[backup] wrote $$out ($$(du -h $$out | cut -f1))"

devkit-limits: ## Print DevKit hard local caps
	@echo "KSwitch DevKit caps"
	@echo "  agents: 10"
	@echo "  mcps:   10"
	@echo "  tools:  100"
	@echo "  skills: 100"

developer-limits: devkit-limits

licence-terms: ## Print DevKit licence summary and file paths
	@echo "KSwitch DevKit licence"
	@echo "  source-available: yes"
	@echo "  open source:      no"
	@echo "  Commercial use:   outside DevKit; requires a scoped KSwitch POC engagement or separate written agreement"
	@echo "  permitted use:    non-commercial local development, testing, education, demos, SDK integration, and non-commercial evaluation"
	@echo "  terms:"
	@echo "    ../LICENSE.md"
	@echo "    ../LICENSES/KSWITCH-DEVKIT-LICENSE.md"
	@echo "    ../COMMERCIAL-USE.md"

# ─── Internal helper used by integration tests (NOT public UX) ───────
clean-state: ## (test-only) Remove ./state/initial-admin.txt without going through Keycloak
	@rm -f $(STATE_DIR)/initial-admin.txt
	@echo "[clean-state] removed $(STATE_DIR)/initial-admin.txt"
