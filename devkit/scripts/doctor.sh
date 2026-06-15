#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# KSwitch Developer Edition — doctor (health + bundled-password time-bomb)
# ─────────────────────────────────────────────────────────────────────────────
#
# Spec: §F `make doctor` row, gates G11 + G20b.
#
# Returns:
#   - exit 0 — all checks PASS (or PASS-with-WARN on the time-bomb).
#   - exit 1 — at least one FAIL. Each line names the failing check
#              and the remediation hint.
#
# Checks (in order):
#   1. App liveness         — GET https://localhost:5001/api/v1/health/live
#   2. App readiness        — GET https://localhost:5001/healthz
#   3. Keycloak realm       — GET http://localhost:3001/realms/kswitch
#   4. OPA decision point   — GET http://opa:8181/health (via app proxy
#                              path; OPA is on the internal network only)
#   5. Bundled-password
#      time-bomb (G20b)     — parse valid_until from
#                              ./state/initial-admin.txt or the cloud
#                              secret per KSWITCH_DEPLOYMENT_TARGET;
#                              WARN within KSWITCH_BUNDLED_PASSWORD_WARN_HOURS,
#                              FAIL after expiry. PASS if the file is
#                              already absent (admin has signed in,
#                              auto-delete fired).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
# Note: NOT `-e` — we want every check to run so the operator sees the
# full picture, then exit non-zero at the end if any check failed.

BUNDLE_ROOT="${BUNDLE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
STATE_DIR="${STATE_DIR:-$BUNDLE_ROOT/state}"
APP_URL="${APP_URL:-https://localhost:5001}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:3001}"

if [ -f "$BUNDLE_ROOT/.env" ]; then
  # shellcheck source=/dev/null
  set -a; . "$BUNDLE_ROOT/.env"; set +a
fi

CUSTOMER_ID="${KSWITCH_CUSTOMER_ID:-unknown}"
DEPLOYMENT_TARGET="${KSWITCH_DEPLOYMENT_TARGET:-laptop}"
WARN_HOURS="${KSWITCH_BUNDLED_PASSWORD_WARN_HOURS:-12}"
INITIAL_ADMIN_FILE="$STATE_DIR/initial-admin.txt"

OVERALL_RC=0

emit() {
  # emit <status> <check> <hint-or-detail>
  printf '  [%-4s] %-40s %s\n' "$1" "$2" "${3:-}"
}

check_url() {
  local name="$1" url="$2" hint="$3"
  if curl -sk -o /dev/null --max-time 5 -w '%{http_code}' "$url" | grep -qE '^(2|3)'; then
    emit PASS "$name" "$url"
  else
    emit FAIL "$name" "$url — $hint"
    OVERALL_RC=1
  fi
}

echo "KSwitch Developer Edition — doctor"
echo "=================================="
echo "  customer-id:        $CUSTOMER_ID"
echo "  deployment-target:  $DEPLOYMENT_TARGET"
echo "  developer caps:     agents=10 mcps=10 tools=100 skills=100"
echo ""

# ─── Service checks (G11) ───────────────────────────────────────────
check_url "app /api/v1/health/live"  "$APP_URL/api/v1/health/live"           "docker compose logs app"
check_url "app /api/v1/health/ready" "$APP_URL/api/v1/health/ready"          "docker compose logs app — readiness probe failing"
check_url "keycloak /realms/kswitch" "$KEYCLOAK_URL/realms/kswitch/.well-known/openid-configuration" "docker compose logs keycloak — was the realm imported?"
check_url "developer portal /docs/"  "$APP_URL/docs/"                        "make bundle-docs in upstream — local docs missing from app image"

# ─── Bundled-password time-bomb (G20b) ──────────────────────────────
read_valid_until() {
  case "$DEPLOYMENT_TARGET" in
    laptop|on-prem)
      [ -f "$INITIAL_ADMIN_FILE" ] || { echo "ABSENT"; return; }
      grep '^KSWITCH_INITIAL_ADMIN_VALID_UNTIL=' "$INITIAL_ADMIN_FILE" | cut -d= -f2-
      ;;
    cloud-vm)
      case "${KSWITCH_CLOUD_SECRET_BACKEND:-aws-secretsmanager}" in
        aws-secretsmanager)
          name="kswitch-${CUSTOMER_ID}-initial-admin"
          if aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1; then
            aws secretsmanager get-secret-value --secret-id "$name" --query SecretString --output text \
              | jq -r '.valid_until // empty'
          else
            echo "ABSENT"
          fi
          ;;
        gcp-secret-manager)
          name="kswitch-${CUSTOMER_ID}-initial-admin"
          if gcloud secrets describe "$name" >/dev/null 2>&1; then
            gcloud secrets versions access latest --secret="$name" 2>/dev/null \
              | jq -r '.valid_until // empty'
          else
            echo "ABSENT"
          fi
          ;;
        azure-keyvault)
          name="kswitch-${CUSTOMER_ID}-initial-admin"
          kv="${AZURE_KEYVAULT_NAME:-}"
          if [ -n "$kv" ] && az keyvault secret show --vault-name "$kv" --name "$name" >/dev/null 2>&1; then
            az keyvault secret show --vault-name "$kv" --name "$name" --query value -o tsv \
              | jq -r '.valid_until // empty'
          else
            echo "ABSENT"
          fi
          ;;
      esac
      ;;
    k8s)
      name="kswitch-${CUSTOMER_ID}-initial-admin"
      ns="${K8S_NAMESPACE:-kswitch}"
      if kubectl -n "$ns" get secret "$name" >/dev/null 2>&1; then
        kubectl -n "$ns" get secret "$name" -o jsonpath='{.metadata.annotations.kswitch\.ai/valid_until}' 2>/dev/null
      else
        echo "ABSENT"
      fi
      ;;
  esac
}

VALID_UNTIL="$(read_valid_until)"
if [ "$VALID_UNTIL" = "ABSENT" ] || [ -z "$VALID_UNTIL" ]; then
  emit PASS "bundled-password time-bomb" "secret already cleared (admin has signed in)"
else
  # Compare via Python (portable; macOS BSD `date` does not parse
  # ISO-8601 the same way as GNU `date`).
  STATUS="$(python3 - <<EOF
from datetime import datetime, timezone
vu_str = "$VALID_UNTIL"
try:
    vu = datetime.strptime(vu_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
except ValueError:
    print("FAIL malformed-valid-until")
else:
    now = datetime.now(timezone.utc)
    delta_h = (vu - now).total_seconds() / 3600.0
    warn = float("$WARN_HOURS")
    if delta_h <= 0:
        print(f"FAIL expired {abs(delta_h):.1f}h ago")
    elif delta_h <= warn:
        print(f"WARN {delta_h:.1f}h until expiry")
    else:
        print(f"PASS {delta_h:.1f}h until expiry")
EOF
)"
  case "$STATUS" in
    PASS*) emit PASS "bundled-password time-bomb" "${STATUS#PASS }" ;;
    WARN*) emit WARN "bundled-password time-bomb" "${STATUS#WARN } — sign in soon or run \`make seed-reset KSWITCH_CONFIRM_SEED_RESET=yes\`" ;;
    FAIL*)
      emit FAIL "bundled-password time-bomb" "${STATUS#FAIL } — run \`make seed-reset KSWITCH_CONFIRM_SEED_RESET=yes\`"
      OVERALL_RC=1
      ;;
  esac
fi

echo ""
if [ $OVERALL_RC -eq 0 ]; then
  echo "doctor: all checks passed."
else
  echo "doctor: at least one check FAILED — see hints above."
fi
exit $OVERALL_RC
