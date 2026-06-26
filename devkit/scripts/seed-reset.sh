#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# KSwitch DevKit — seed-reset script (destructive recovery)
# ─────────────────────────────────────────────────────────────────────────────
#
# Spec: §F `make seed-reset` row, gates G21a + R9b.
#
# Behaviour:
#
#   - Refuses to run unless KSWITCH_CONFIRM_SEED_RESET=yes is set in the
#     environment. Without it: non-zero exit, no Keycloak mutation, no
#     file change.
#
#   - With confirmation:
#       1. Look up the existing admin user in Keycloak by username.
#       2. DELETE the user (Keycloak admin REST API).
#       3. Remove the bundled secret (./state/initial-admin.txt or the
#          cloud-secret entry per KSWITCH_DEPLOYMENT_TARGET).
#       4. Emit `governance.admin.password_reset_initiated` to the
#          KSwitch audit_log table via the app's internal audit endpoint.
#       5. Re-invoke seed.sh to mint fresh credentials.
#
#   - The audit-event contract for the K8s sidecar (Wave 3 Agent G):
#       event_type = "governance.admin.password_reset_initiated"
#       event_by   = ADMIN_USERNAME  (principal email; principal field
#                                     is `event_by`, not `principal_email`
#                                     — see seed.sh comment for rationale)
#
# Documented operator path if the bundled password is lost or the
# +24h time-bomb has fired before first login.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BUNDLE_ROOT="${BUNDLE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCRIPTS_DIR="$BUNDLE_ROOT/scripts"
STATE_DIR="${STATE_DIR:-$BUNDLE_ROOT/state}"
APP_URL="${APP_URL:-https://localhost:5001}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:3001}"

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

log()  { printf '[seed-reset] %s\n' "$*"; }
fail() { printf '[seed-reset] FATAL: %s\n' "$*" >&2; exit 1; }

# ─── G21a: explicit confirmation gate ───────────────────────────────
if [ "${KSWITCH_CONFIRM_SEED_RESET:-}" != "yes" ]; then
  cat >&2 <<EOF
[seed-reset] REFUSING — destructive recovery is never accidental.

This target will:
  1. DELETE the Keycloak admin user '$ADMIN_USERNAME'.
  2. Remove the bundled secret (./state/initial-admin.txt or your
     cloud-secret entry).
  3. Emit governance.admin.password_reset_initiated to audit_log.
  4. Re-run seed.sh to mint fresh credentials.

To proceed, re-run with explicit confirmation:

    make seed-reset KSWITCH_CONFIRM_SEED_RESET=yes

EOF
  exit 1
fi

# ─── Authenticate to Keycloak ────────────────────────────────────────
KC_TOKEN="$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli&grant_type=password&username=${KEYCLOAK_ADMIN}&password=${KEYCLOAK_ADMIN_PASSWORD}" \
  | jq -r .access_token)"
[ -n "$KC_TOKEN" ] && [ "$KC_TOKEN" != "null" ] || \
  fail "Keycloak admin auth failed at $KEYCLOAK_URL"

# ─── Lookup existing admin user ─────────────────────────────────────
EXISTING_USER_ID="$(curl -s -H "Authorization: Bearer $KC_TOKEN" \
  "${KEYCLOAK_URL}/admin/realms/kswitch/users?username=${ADMIN_USERNAME}&exact=true" \
  | jq -r 'if length>0 then .[0].id else empty end')"

if [ -n "${EXISTING_USER_ID:-}" ]; then
  log "deleting Keycloak user '$ADMIN_USERNAME' (id=$EXISTING_USER_ID)"
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -X DELETE \
    -H "Authorization: Bearer $KC_TOKEN" \
    "${KEYCLOAK_URL}/admin/realms/kswitch/users/${EXISTING_USER_ID}")"
  [ "$CODE" = "204" ] || fail "Keycloak user delete returned HTTP $CODE"
else
  log "no existing Keycloak user '$ADMIN_USERNAME' — proceeding to mint fresh credentials"
fi

# ─── Remove the bundled secret per deployment target ────────────────
case "$DEPLOYMENT_TARGET" in
  laptop|on-prem)
    if [ -f "$INITIAL_ADMIN_FILE" ]; then
      rm -f "$INITIAL_ADMIN_FILE"
      log "removed $INITIAL_ADMIN_FILE"
    fi
    ;;
  cloud-vm)
    case "${KSWITCH_CLOUD_SECRET_BACKEND:-aws-secretsmanager}" in
      aws-secretsmanager)
        name="kswitch-${CUSTOMER_ID}-initial-admin"
        if aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1; then
          aws secretsmanager delete-secret --secret-id "$name" --force-delete-without-recovery >/dev/null
          log "deleted AWS Secrets Manager entry $name"
        fi
        ;;
      gcp-secret-manager)
        name="kswitch-${CUSTOMER_ID}-initial-admin"
        if gcloud secrets describe "$name" >/dev/null 2>&1; then
          gcloud secrets delete "$name" --quiet >/dev/null
          log "deleted GCP Secret Manager entry $name"
        fi
        ;;
      azure-keyvault)
        name="kswitch-${CUSTOMER_ID}-initial-admin"
        kv="${AZURE_KEYVAULT_NAME:?AZURE_KEYVAULT_NAME required}"
        if az keyvault secret show --vault-name "$kv" --name "$name" >/dev/null 2>&1; then
          az keyvault secret delete --vault-name "$kv" --name "$name" >/dev/null
          log "deleted Azure Key Vault $kv/$name"
        fi
        ;;
    esac
    ;;
  k8s)
    name="kswitch-${CUSTOMER_ID}-initial-admin"
    ns="${K8S_NAMESPACE:-kswitch}"
    if kubectl -n "$ns" get secret "$name" >/dev/null 2>&1; then
      kubectl -n "$ns" delete secret "$name" >/dev/null
      log "deleted K8s Secret $ns/$name"
    fi
    ;;
esac

# ─── Emit governance.admin.password_reset_initiated to audit_log ─────
#
# Per the §I.5 audit-watcher sidecar contract (Wave 3 Agent G):
#   event_type = governance.admin.password_reset_initiated
#   event_by   = ADMIN_USERNAME (principal email)
#
# event_by is the principal field — the audit_log schema at
# app/database.py:572 has no `principal_email` column.
#
# §G self-review #2 — same audit-marker pattern as seed.sh: the app's
# boot-path observer (Wave 2 Agent B) consumes the marker file and
# writes the audit_log row idempotently. seed-reset writes the marker
# BEFORE re-invoking seed.sh so the reset event is timestamped before
# the new initial_seed_completed event the new seed produces.
EVENT_DETAIL="$(jq -nc \
  --arg cid "$CUSTOMER_ID" \
  --arg dt  "$DEPLOYMENT_TARGET" \
  '{customer_id:$cid, deployment_target:$dt, reason:"operator-initiated seed-reset"}')"
EVENT_PAYLOAD="$(jq -nc \
  --arg et 'governance.admin.password_reset_initiated' \
  --arg by "$ADMIN_USERNAME" \
  --argjson detail "$EVENT_DETAIL" \
  '{event_type:$et, event_by:$by, event_detail:$detail}')"

printf 'AUDIT_EVENT: %s\n' "$EVENT_PAYLOAD"

mkdir -p "$STATE_DIR/audit-markers"
MARKER_FILE="$STATE_DIR/audit-markers/password_reset_initiated.$(date -u +%Y%m%dT%H%M%SZ).json"
printf '%s\n' "$EVENT_PAYLOAD" > "$MARKER_FILE"
chmod 600 "$MARKER_FILE"
log "wrote audit marker $MARKER_FILE — app boot observer will insert audit_log row"

# ─── Re-mint fresh credentials by re-invoking seed.sh ────────────────
log "minting fresh admin credentials..."
exec "$SCRIPTS_DIR/seed.sh"
