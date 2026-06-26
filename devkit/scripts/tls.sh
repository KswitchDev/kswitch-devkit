#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# KSwitch DevKit — self-signed TLS generation (G22)
# ─────────────────────────────────────────────────────────────────────────────
#
# Spec: §F `make tls` row + "TLS choice rationale".
#
# - Uses `openssl` only — no mkcert (which would install a local CA
#   into the OS trust store, an invasive change often blocked by
#   enterprise workstation policy).
# - Browser shows a one-time "Not Secure" warning on first visit; the
#   developer accepts.
# - No-op if ./tls/cert.pem already exists (so the developer's own
#   CA-signed certs survive `make up` re-runs).
# - Cert lifetime: 825 days (Apple-recommended max).
# - Subject Alternative Names cover localhost + 127.0.0.1 + ::1, so
#   curl -k and modern browsers accept the cert as valid for the
#   bundled access pattern.
#
# G22 asserts the OS trust store is unchanged. We never call `security
# add-trusted-cert` (macOS), `update-ca-certificates` (Debian-family),
# or `trust anchor` (Fedora-family). This script touches only files
# under ./tls/.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BUNDLE_ROOT="${BUNDLE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TLS_DIR="${TLS_DIR:-$BUNDLE_ROOT/tls}"

CERT_PATH="$TLS_DIR/cert.pem"
KEY_PATH="$TLS_DIR/key.pem"

log() { printf '[tls] %s\n' "$*"; }

mkdir -p "$TLS_DIR"

if [ -f "$CERT_PATH" ]; then
  log "$CERT_PATH already exists — leaving alone (no-op, G22)"
  log "to regenerate: rm $CERT_PATH $KEY_PATH && make tls"
  exit 0
fi

log "generating self-signed cert via openssl (no OS trust-store changes)"

# Generate Ed25519 private key (FIPS 186-5 / RFC 8032). Falls back to
# RSA-2048 if the local openssl is too old to know Ed25519 (pre-1.1.1,
# rare in 2026 but possible on RHEL 7).
if openssl genpkey -algorithm ED25519 -out "$KEY_PATH" 2>/dev/null; then
  log "key: Ed25519 (preferred)"
else
  log "key: RSA-2048 (Ed25519 unsupported by local openssl)"
  openssl genrsa -out "$KEY_PATH" 2048
fi
chmod 600 "$KEY_PATH"

# Subject Alternative Names: localhost + IPv4 loopback + IPv6 loopback
SAN_CONF="$(mktemp -t kswitch-tls-san.XXXXXX)"
cat > "$SAN_CONF" <<EOF
[req]
distinguished_name = dn
prompt = no
req_extensions = v3_req
[dn]
CN = localhost
O  = KSwitch DevKit
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EOF

openssl req -new -x509 -days 825 \
  -key "$KEY_PATH" \
  -out "$CERT_PATH" \
  -config "$SAN_CONF" \
  -extensions v3_req >/dev/null 2>&1

rm -f "$SAN_CONF"

log "wrote $CERT_PATH (825-day self-signed)"
log "wrote $KEY_PATH (mode 600)"
