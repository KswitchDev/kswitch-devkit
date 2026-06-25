#!/usr/bin/env bash
set -euo pipefail

SPIRE_SERVER_SOCKET="${SPIRE_SERVER_SOCKET:-/tmp/spire-server/private/api.sock}"
SPIRE_AGENT_CONFIG="${SPIRE_AGENT_CONFIG:-/etc/spire/agent/agent.conf}"
SPIRE_AGENT_SPIFFE_ID="${SPIRE_AGENT_SPIFFE_ID:-spiffe://kswitch.ai/agent/local}"

if [ ! -S "$SPIRE_SERVER_SOCKET" ]; then
  echo "ERROR: SPIRE server admin socket not found at $SPIRE_SERVER_SOCKET" >&2
  echo "       Mount the spire-server-socket named volume at /tmp/spire-server/private." >&2
  exit 64
fi

if [ ! -f "$SPIRE_AGENT_CONFIG" ]; then
  echo "ERROR: SPIRE agent config not found at $SPIRE_AGENT_CONFIG" >&2
  exit 64
fi

TOKEN_JSON=$(/opt/spire/bin/spire-server token generate \
  -spiffeID "$SPIRE_AGENT_SPIFFE_ID" \
  -socketPath "$SPIRE_SERVER_SOCKET" \
  -output json 2>/dev/null) || {
    echo "ERROR: failed to mint SPIRE join token from $SPIRE_SERVER_SOCKET" >&2
    exit 65
  }

TOKEN=$(echo "$TOKEN_JSON" | grep -oE '[a-f0-9-]{36}' | head -n1)
unset TOKEN_JSON

if [ -z "$TOKEN" ]; then
  echo "ERROR: SPIRE join token was empty after generation" >&2
  exit 66
fi

echo "spire-agent-wrapper: minted join token (redacted; local-only)"

exec /opt/spire/bin/spire-agent run \
  -config "$SPIRE_AGENT_CONFIG" \
  -joinToken "$TOKEN"
