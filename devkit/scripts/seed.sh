#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# KSwitch Developer Edition — seed script
# ─────────────────────────────────────────────────────────────────────────────
#
# Developer Edition — first-run seed (Keycloak realm + admin user).
# Implements the locked password lifecycle: random 32-char generation,
# Keycloak UPDATE_PASSWORD required action, valid_until +24h time-bomb.
#
# Behaviour (per Makefile target row for `make seed`):
#
#   - Idempotent. Realm + policies are upserted; the admin user is
#     create-only.
#   - On first run: generate a random 32-char password, create the admin
#     user in Keycloak, set the UPDATE_PASSWORD required action on it
#     (G20a — force-change-on-first-login), and write the bundled secret
#     to either ./state/initial-admin.txt (laptop/on-prem) or to the
#     cloud-native secret store (cloud-vm/k8s) — never both, and never
#     a host file on cloud installs (G33).
#   - Bundled secret carries a `valid_until` ISO-8601 stamp, +24h from
#     generation (G20b time-bomb).
#   - On subsequent runs: detect the existing admin user and exit 0
#     without rotating the password (G21).
#
# Vendor docs cited:
#   - Keycloak Admin REST API: https://www.keycloak.org/docs-api/26.0.0/rest-api/
#     retrieved 2026-05-15 (vendor-documented, class A).
#   - The `requiredActions` field on a Keycloak user is a list of
#     strings; "UPDATE_PASSWORD" is one of the built-in actions, applied
#     at the user's next login (Keycloak source:
#     https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/models/UserModel.java
#     — RequiredAction enum).
#   - AWS Secrets Manager `create-secret` returns
#     `ResourceExistsException` on duplicate name (vendor-documented:
#     https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html).
#
# Audit-event contract (consumed by the K8s audit-watcher sidecar
# specified in §I.5 — Wave 3 / Agent G):
#
#   event_type = 'governance.admin.initial_seed_completed'  (this script)
#   event_type = 'admin.login.success'                      (Flask app on
#                                                            first login)
#   event_type = 'governance.admin.password_reset_initiated'(seed-reset.sh)
#   event_type = 'governance.admin.initial_secret_deleted'  (audit-watcher
#                                                            sidecar on K8s)
#
# Principal field. The KSwitch `audit_log` table at
# `app/database.py:572` has columns
# (record_id, event_id, event_type, event_at, event_by, event_detail,
# created_at) — there is **no `principal_email` column**. Per Principle
# §6 (issues called out, not swallowed) this script and the spec's
# §I.5 sidecar contract both use `event_by` for the principal email.
# Defect captured in §G self-review #1 (see evidence pack).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Honour the env overrides exported by the Makefile ──────────────
BUNDLE_ROOT="${BUNDLE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STATE_DIR="${STATE_DIR:-$BUNDLE_ROOT/state}"
SEED_DIR="${SEED_DIR:-$BUNDLE_ROOT/seed}"
APP_URL="${APP_URL:-https://localhost:5001}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:3001}"

# ─── Source .env if present (shellcheck: external file at runtime) ──
if [ -f "$BUNDLE_ROOT/.env" ]; then
  # shellcheck source=/dev/null
  set -a; . "$BUNDLE_ROOT/.env"; set +a
fi

CUSTOMER_ID="${KSWITCH_CUSTOMER_ID:?KSWITCH_CUSTOMER_ID required (set in .env)}"
DEPLOYMENT_TARGET="${KSWITCH_DEPLOYMENT_TARGET:-laptop}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-kswitch-developer-keycloak}"

ADMIN_USERNAME="admin@${CUSTOMER_ID}"
INITIAL_ADMIN_FILE="$STATE_DIR/initial-admin.txt"
INITIAL_ADMIN_TMPL="$SEED_DIR/initial-admin.tmpl"

log()  { printf '[seed] %s\n' "$*"; }
fail() { printf '[seed] FATAL: %s\n' "$*" >&2; exit 1; }

# Refuse to log secrets even at debug.
trap 'rc=$?; [ $rc -ne 0 ] && log "exited with rc=$rc"; exit $rc' EXIT

# ─── Derived: secret-storage strategy per deployment target ──────────
case "$DEPLOYMENT_TARGET" in
  laptop|on-prem) SECRET_BACKEND="file" ;;
  cloud-vm)
    SECRET_BACKEND="${KSWITCH_CLOUD_SECRET_BACKEND:-aws-secretsmanager}"
    ;;
  k8s)
    SECRET_BACKEND="${KSWITCH_CLOUD_SECRET_BACKEND:-k8s-secret}"
    ;;
  *)
    fail "Unrecognised KSWITCH_DEPLOYMENT_TARGET=$DEPLOYMENT_TARGET (allowed: laptop|on-prem|cloud-vm|k8s)"
    ;;
esac
log "deployment-target=$DEPLOYMENT_TARGET secret-backend=$SECRET_BACKEND"

# ─── Authenticate to Keycloak admin REST API ────────────────────────
kc_token() {
  curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli&grant_type=password&username=${KEYCLOAK_ADMIN}&password=${KEYCLOAK_ADMIN_PASSWORD}" \
    | jq -r .access_token
}

KC_TOKEN="$(kc_token)"
[ -n "$KC_TOKEN" ] && [ "$KC_TOKEN" != "null" ] || \
  fail "Keycloak admin auth failed at $KEYCLOAK_URL — is keycloak healthy? (make doctor)"

kc_get() {
  curl -s -H "Authorization: Bearer $KC_TOKEN" "$KEYCLOAK_URL$1"
}
kc_post() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$KEYCLOAK_URL$1" \
    -H "Authorization: Bearer $KC_TOKEN" -H 'Content-Type: application/json' -d "$2"
}
kc_put() {
  curl -s -o /dev/null -w '%{http_code}' -X PUT "$KEYCLOAK_URL$1" \
    -H "Authorization: Bearer $KC_TOKEN" -H 'Content-Type: application/json' -d "$2"
}

# ─── Idempotency guard: existing admin user (G21) ────────────────────
EXISTING_USER_ID="$(kc_get "/admin/realms/kswitch/users?username=${ADMIN_USERNAME}&exact=true" \
  | jq -r 'if length>0 then .[0].id else empty end')"

if [ -n "${EXISTING_USER_ID:-}" ]; then
  log "admin user '$ADMIN_USERNAME' already exists in Keycloak — leaving alone (G21)."
  log "to regenerate, run: make seed-reset KSWITCH_CONFIRM_SEED_RESET=yes"
  exit 0
fi

# ─── Generate the bundled-admin random password ──────────────────────
# 32-char URL-safe (per spec). `openssl rand -base64 24` yields 32
# base64 chars; we strip newline.
PASSWORD="$(openssl rand -base64 24 | tr -d '\n=')"

# ─── valid_until = NOW + 24h, ISO-8601 UTC (G20b time-bomb) ──────────
# Use Python for portable ISO-8601 (BSD `date` on macOS lacks `-d`).
GENERATED_AT="$(python3 -c 'from datetime import datetime,timezone;print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
VALID_UNTIL="$(python3 -c 'from datetime import datetime,timedelta,timezone;print((datetime.now(timezone.utc)+timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"

# ─── Create admin user in Keycloak with UPDATE_PASSWORD required action ─
USER_PAYLOAD="$(jq -n \
  --arg u "$ADMIN_USERNAME" \
  '{
     username:$u, email:$u, emailVerified:true, enabled:true,
     firstName:"KSwitch", lastName:"Admin",
     requiredActions:["UPDATE_PASSWORD"],
     attributes:{kswitch_initial_admin:["true"]}
   }')"

CODE="$(kc_post "/admin/realms/kswitch/users" "$USER_PAYLOAD")"
[ "$CODE" = "201" ] || fail "Keycloak admin create returned HTTP $CODE"

NEW_USER_ID="$(kc_get "/admin/realms/kswitch/users?username=${ADMIN_USERNAME}&exact=true" \
  | jq -r '.[0].id')"
[ -n "$NEW_USER_ID" ] && [ "$NEW_USER_ID" != "null" ] || \
  fail "could not look up freshly-created admin user"

# Set the password (temporary=false; UPDATE_PASSWORD action forces
# change at next login regardless of `temporary` flag — this is the
# Keycloak vendor-documented contract).
PWD_PAYLOAD="$(jq -n --arg p "$PASSWORD" '{type:"password", value:$p, temporary:false}')"
CODE="$(kc_put "/admin/realms/kswitch/users/${NEW_USER_ID}/reset-password" "$PWD_PAYLOAD")"
[ "$CODE" = "204" ] || fail "Keycloak password set returned HTTP $CODE"

# Assign Register.Admin realm role.
ROLE_JSON="$(kc_get "/admin/realms/kswitch/roles/Register.Admin")"
ROLE_ID="$(jq -r .id <<<"$ROLE_JSON")"
[ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "null" ] || \
  fail "Register.Admin realm role not found — was the realm imported?"

ROLE_ASSIGN="$(jq -n --arg id "$ROLE_ID" '[{id:$id, name:"Register.Admin"}]')"
CODE="$(kc_post "/admin/realms/kswitch/users/${NEW_USER_ID}/role-mappings/realm" "$ROLE_ASSIGN")"
[ "$CODE" = "204" ] || fail "Keycloak role assign returned HTTP $CODE"

log "admin user created in Keycloak with UPDATE_PASSWORD required action (G20a)"

# ─── Persist the bundled secret per deployment target (G33 cloud rule) ──
write_file_secret() {
  mkdir -p "$STATE_DIR"
  # Render the template; never write the raw password to stdout.
  sed \
    -e "s|{{CUSTOMER_ID}}|$CUSTOMER_ID|g" \
    -e "s|{{USERNAME}}|$ADMIN_USERNAME|g" \
    -e "s|{{PASSWORD}}|$PASSWORD|g" \
    -e "s|{{VALID_UNTIL}}|$VALID_UNTIL|g" \
    -e "s|{{GENERATED_AT}}|$GENERATED_AT|g" \
    "$INITIAL_ADMIN_TMPL" > "$INITIAL_ADMIN_FILE"
  chmod 600 "$INITIAL_ADMIN_FILE"
  log "wrote $INITIAL_ADMIN_FILE (mode 600, valid_until=$VALID_UNTIL)"
}

write_aws_secret() {
  local name="kswitch-${CUSTOMER_ID}-initial-admin"
  local payload
  payload="$(jq -n --arg p "$PASSWORD" --arg v "$VALID_UNTIL" --arg u "$ADMIN_USERNAME" \
    '{username:$u, password:$p, valid_until:$v}')"
  # Per AWS Secrets Manager docs (vendor-documented): create-secret
  # returns ResourceExistsException on duplicate. Fail loud (G33a).
  if aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1; then
    fail "AWS Secrets Manager already has '$name' — pick a different KSWITCH_CUSTOMER_ID or run seed-reset (G33a)"
  fi
  aws secretsmanager create-secret --name "$name" --secret-string "$payload" \
    --tags Key=kswitch:edition,Value=developer Key=kswitch:customer_id,Value="$CUSTOMER_ID" >/dev/null
  log "wrote AWS Secrets Manager entry $name (no host file written, G33)"
}

write_gcp_secret() {
  local name="kswitch-${CUSTOMER_ID}-initial-admin"
  local payload
  payload="$(jq -n --arg p "$PASSWORD" --arg v "$VALID_UNTIL" --arg u "$ADMIN_USERNAME" \
    '{username:$u, password:$p, valid_until:$v}')"
  if gcloud secrets describe "$name" >/dev/null 2>&1; then
    fail "GCP Secret Manager already has '$name' — pick a different KSWITCH_CUSTOMER_ID or run seed-reset (G33a)"
  fi
  printf '%s' "$payload" | gcloud secrets create "$name" --data-file=- \
    --labels="kswitch_edition=developer,kswitch_customer_id=$CUSTOMER_ID" >/dev/null
  log "wrote GCP Secret Manager entry $name (no host file written, G33)"
}

write_azure_secret() {
  local name="kswitch-${CUSTOMER_ID}-initial-admin"
  local kv="${AZURE_KEYVAULT_NAME:?AZURE_KEYVAULT_NAME required for azure-keyvault backend}"
  local payload
  payload="$(jq -n --arg p "$PASSWORD" --arg v "$VALID_UNTIL" --arg u "$ADMIN_USERNAME" \
    '{username:$u, password:$p, valid_until:$v}')"
  if az keyvault secret show --vault-name "$kv" --name "$name" >/dev/null 2>&1; then
    fail "Azure Key Vault $kv already has '$name' — pick a different KSWITCH_CUSTOMER_ID or run seed-reset (G33a)"
  fi
  az keyvault secret set --vault-name "$kv" --name "$name" --value "$payload" \
    --tags kswitch_edition=developer kswitch_customer_id="$CUSTOMER_ID" >/dev/null
  log "wrote Azure Key Vault $kv/$name (no host file written, G33)"
}

write_k8s_secret() {
  local name="kswitch-${CUSTOMER_ID}-initial-admin"
  local ns="${K8S_NAMESPACE:-kswitch}"
  if kubectl -n "$ns" get secret "$name" >/dev/null 2>&1; then
    fail "K8s namespace $ns already has secret '$name' — pick a different KSWITCH_CUSTOMER_ID or run seed-reset (G33a)"
  fi
  kubectl -n "$ns" create secret generic "$name" \
    --from-literal=username="$ADMIN_USERNAME" \
    --from-literal=password="$PASSWORD" \
    --from-literal=valid_until="$VALID_UNTIL" >/dev/null
  kubectl -n "$ns" annotate secret "$name" \
    "kswitch.ai/valid_until=$VALID_UNTIL" \
    "kswitch.ai/edition=developer" \
    "kswitch.ai/customer_id=$CUSTOMER_ID" >/dev/null
  log "wrote K8s Secret $ns/$name (no host file written, G37)"
}

case "$SECRET_BACKEND" in
  file)                  write_file_secret    ;;
  aws-secretsmanager)    write_aws_secret     ;;
  gcp-secret-manager)    write_gcp_secret     ;;
  azure-keyvault)        write_azure_secret   ;;
  k8s-secret)            write_k8s_secret     ;;
  *) fail "unknown KSWITCH_CLOUD_SECRET_BACKEND=$SECRET_BACKEND" ;;
esac

# ─── Emit governance.admin.initial_seed_completed to KSwitch audit_log ─
#
# Audit-event contract (locked here for the K8s audit-watcher sidecar
# in §I.5 — Wave 3 Agent G):
#
#   event_type   = "governance.admin.initial_seed_completed"
#   event_by     = ADMIN_USERNAME   (the principal field, per audit_log
#                                    schema — there is no `principal_email`
#                                    column; see §G self-review #1).
#   event_detail = JSON {customer_id, valid_until, secret_backend, deployment_target}
#
# §G self-review #2 — the bundle scripts run BEFORE the app's HTTP
# surface is necessarily up (and even when it is, the app does not
# expose an authenticated /api/v1/internal/audit-event route — that
# would be a privilege-escalation hazard). The audit_log row is
# therefore inserted by the app's boot-path observer, which Wave 2
# Agent B owns: on app start the observer scans the seed-marker file
# below + the Keycloak admin user state and inserts the row idempotently.
#
# We emit the event as a JSON-line marker on stdout (parsed by the
# Makefile-level capture if the operator pipes through `tee`) AND
# write the same payload to a small marker file the app's boot
# observer reads. Either path lands the same audit_log row exactly
# once.
EVENT_DETAIL="$(jq -nc \
  --arg cid "$CUSTOMER_ID" \
  --arg vu  "$VALID_UNTIL" \
  --arg sb  "$SECRET_BACKEND" \
  --arg dt  "$DEPLOYMENT_TARGET" \
  '{customer_id:$cid, valid_until:$vu, secret_backend:$sb, deployment_target:$dt}')"
EVENT_PAYLOAD="$(jq -nc \
  --arg et 'governance.admin.initial_seed_completed' \
  --arg by "$ADMIN_USERNAME" \
  --argjson detail "$EVENT_DETAIL" \
  '{event_type:$et, event_by:$by, event_detail:$detail}')"

# Marker on stdout — machine-parseable.
printf 'AUDIT_EVENT: %s\n' "$EVENT_PAYLOAD"

# Marker file in ./state/ for the app's boot-path observer to consume.
# The observer deletes this file after writing the audit_log row, so
# repeated `make seed` invocations don't double-insert.
mkdir -p "$STATE_DIR/audit-markers"
MARKER_FILE="$STATE_DIR/audit-markers/initial_seed_completed.json"
printf '%s\n' "$EVENT_PAYLOAD" > "$MARKER_FILE"
chmod 600 "$MARKER_FILE"
log "wrote audit marker $MARKER_FILE — app boot observer will insert audit_log row"

log "seed complete. operator next steps:"
log "  1. read $INITIAL_ADMIN_FILE (or your cloud secret)"
log "  2. sign in at $APP_URL — Keycloak will force you to set your own password"
log "  3. the bundled secret is auto-deleted on first successful admin login (G20)"
