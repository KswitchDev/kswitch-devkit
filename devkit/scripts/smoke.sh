#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# KSwitch Developer Edition — smoke probe
# ─────────────────────────────────────────────────────────────────────────────
#
# Spec: §F `make smoke` row.
#
# Hits 10 representative endpoints in ~15s. API-only — no Playwright,
# no browser dependencies. Self-contained.
#
# Returns:
#   - exit 0 — all 10 probes return 2xx or the expected 4xx for
#              auth-gated endpoints (which prove the gate is up).
#   - exit 1 — at least one probe returned an unexpected status.
#
# This is the probe `helm test kswitch -n kswitch` runs on K8s as
# well, so green smoke means the same thing across every deployment
# target (per §I.1).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

APP_URL="${APP_URL:-https://localhost:5001}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:3001}"

RC=0
PASS=0
FAIL=0

probe() {
  local name="$1" url="$2" expected="$3"
  local code
  code="$(curl -sk -o /dev/null --max-time 10 -w '%{http_code}' "$url" || echo 000)"
  # `expected` is a regex. e.g. "2.." for any 2xx, "200|401" for either.
  if [[ "$code" =~ ^($expected)$ ]]; then
    printf '  [PASS] %-45s HTTP %s\n' "$name" "$code"
    PASS=$((PASS+1))
  else
    printf '  [FAIL] %-45s HTTP %s (expected %s) — %s\n' "$name" "$code" "$expected" "$url"
    FAIL=$((FAIL+1))
    RC=1
  fi
}

echo "KSwitch Developer Edition — smoke probe"
echo "=================================="

# 1. App liveness — public, must return 2xx.
probe "app /api/v1/health/live"          "$APP_URL/api/v1/health/live"            "2.."
# 2. App readiness — public, must return 2xx.
#    Note: §G self-review #3 — `/healthz` is not a real route in the
#    app (only /api/v1/health/{live,ready,/}). The readiness probe
#    targets /api/v1/health/ready directly, which the parent repo's
#    app/routes/health.py:104 owns.
probe "app /api/v1/health/ready"         "$APP_URL/api/v1/health/ready"           "2.."
# 3. Developer portal — public, must render (G15).
probe "developer portal /docs/"          "$APP_URL/docs/"                         "2.."
# 4. Keycloak realm well-known — public.
probe "keycloak well-known"              "$KEYCLOAK_URL/realms/kswitch/.well-known/openid-configuration" "2.."
# 5. App index — public, returns the SPA shell.
probe "app /"                            "$APP_URL/"                              "2.."
# 6. Auth-gated read endpoint — must 401 (proves the gate works).
probe "agents (gated)"                   "$APP_URL/api/v1/agents"                 "401"
# 7. Auth-gated read endpoint — must 401.
probe "mcps (gated)"                     "$APP_URL/api/v1/mcps"                   "401"
# 8. Auth-gated read endpoint — must 401.
probe "policies (gated)"                 "$APP_URL/api/v1/policies"               "401"
# 9. Catalog — public listing.
probe "catalog tools"                    "$APP_URL/api/v1/catalog/tools"          "2..|401"
# 10. AuthZen PDP — must 405 (POST-only) or 401.
probe "authzen pdp"                      "$APP_URL/access/v1/evaluation"          "405|401|400"

echo ""
echo "smoke: $PASS passed, $FAIL failed."
exit $RC
