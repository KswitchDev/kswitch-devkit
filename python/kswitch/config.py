"""
KSwitch SDK configuration — env-var backed with sensible defaults.

PR-11 (Revocation Sync): Adds revocation sync configuration.

All values are read from environment variables at import time.
Override by setting env vars before importing kswitch.

Environment variables:
    KSWITCH_BASE_URL                    KSwitch server base URL
    KSWITCH_REVOCATION_SYNC_ENABLED     Enable background sync worker (default: true)
    KSWITCH_REVOCATION_SYNC_INTERVAL    Poll interval in seconds (default: 30)
    KSWITCH_REVOCATION_SYNC_STALE_SECS  Seconds before sync is "stale" (default: 300)
    KSWITCH_REVOCATION_STALE_MODE       Behavior on stale sync: warn|deny|conditional (default: warn)
    KSWITCH_CONTEXT_INVALIDATION_SYNC_ENABLED
                                        Enable context invalidation sync (default: true)
    KSWITCH_CONTEXT_INVALIDATION_SYNC_INTERVAL
                                        Poll interval in seconds (default: revocation interval)
    KSWITCH_LOCAL_PDP_ENABLED           Enable local PDP evaluation (default: false)
"""
from __future__ import annotations

import os


def _bool(key: str, default: bool) -> bool:
    val = os.environ.get(key, "").lower()
    if val in ("true", "1", "yes"):
        return True
    if val in ("false", "0", "no"):
        return False
    return default


def _int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _str(key: str, default: str) -> str:
    return os.environ.get(key, default)


# ── Revocation sync configuration ─────────────────────────────────────────────

#: Enable/disable background revocation sync worker.
REVOCATION_SYNC_ENABLED: bool = _bool("KSWITCH_REVOCATION_SYNC_ENABLED", True)

#: How often (seconds) to check the server revocation version endpoint.
#: Set lower for higher-risk environments. Default: 30s.
REVOCATION_SYNC_INTERVAL: int = _int("KSWITCH_REVOCATION_SYNC_INTERVAL", 30)

#: Seconds of sync gap before the revocation state is considered stale.
#: After this threshold, stale-mode behavior is triggered. Default: 5× sync interval.
REVOCATION_STALE_THRESHOLD: int = _int(
    "KSWITCH_REVOCATION_SYNC_STALE_SECS",
    REVOCATION_SYNC_INTERVAL * 5,
)

#: Behavior when revocation sync is stale beyond REVOCATION_STALE_THRESHOLD.
#: warn       — log warning, continue with local allow/deny (default for dev/test)
#: deny       — deny all decisions until sync recovers (strict/protected mode)
#: conditional — route to server escalation until sync recovers
REVOCATION_STALE_MODE: str = _str("KSWITCH_REVOCATION_STALE_MODE", "warn")

# ── Context-pack invalidation sync configuration ─────────────────────────────

#: Enable/disable background context-pack invalidation sync worker.
CONTEXT_INVALIDATION_SYNC_ENABLED: bool = _bool("KSWITCH_CONTEXT_INVALIDATION_SYNC_ENABLED", True)

#: How often (seconds) to check the server context invalidation version endpoint.
CONTEXT_INVALIDATION_SYNC_INTERVAL: int = _int(
    "KSWITCH_CONTEXT_INVALIDATION_SYNC_INTERVAL",
    REVOCATION_SYNC_INTERVAL,
)

# ── Local PDP ──────────────────────────────────────────────────────────────────

#: Enable local PDP evaluation inside the SDK process.
LOCAL_PDP_ENABLED: bool = _bool("KSWITCH_LOCAL_PDP_ENABLED", False)

# ── Audit forwarding configuration (PR-12) ────────────────────────────────────

#: Enable async forwarding of SDK audit events to the central server.
AUDIT_FORWARDING_ENABLED: bool = _bool("KSWITCH_AUDIT_FORWARDING_ENABLED", False)

#: Override the audit ingestion URL. Defaults to BASE_URL + /api/v1/sdk/audit/events.
AUDIT_INGEST_URL: str = _str("KSWITCH_AUDIT_INGEST_URL", "")

#: Number of events per batch sent to server.
AUDIT_BATCH_SIZE: int = _int("KSWITCH_AUDIT_BATCH_SIZE", 10)

#: Seconds between batch flushes (even if batch not full).
AUDIT_FLUSH_INTERVAL: int = _int("KSWITCH_AUDIT_FLUSH_INTERVAL_SECONDS", 5)

#: Max retry attempts per batch before dropping.
AUDIT_MAX_RETRIES: int = _int("KSWITCH_AUDIT_MAX_RETRIES", 5)

# ── Server base URL ────────────────────────────────────────────────────────────

BASE_URL: str = _str("KSWITCH_BASE_URL", "https://localhost:5001")
