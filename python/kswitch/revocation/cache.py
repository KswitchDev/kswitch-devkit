"""
Local revocation cache — in-process O(1) lookup for killed/suspended agents.

Push-based: KSwitchRuntime.sync_revocations() fetches from server and populates.
Disk persistence: ~/.kswitch/revocation/revoked.json (survives process restart).

PR-11 (Revocation Sync): Adds apply_server_state() for atomic batch update from
the background sync worker, plus sync metadata (last_synced_at, server_version).

The cache is checked BEFORE any bundle/context evaluation.
A revoked agent is denied without any further evaluation.
"""
import json
import os
import threading
import time
from typing import Optional

_DEFAULT_REVOCATION_DIR = os.path.expanduser("~/.kswitch/revocation")
_REVOCATION_FILE = "revoked.json"
_REVOCATION_EXPIRY = 86400  # 24 hours


class LocalRevocationCache:
    """Thread-safe in-process revocation cache with disk persistence."""

    def __init__(self, revocation_dir: str = _DEFAULT_REVOCATION_DIR):
        self._dir = revocation_dir
        self._lock = threading.RLock()
        self._revoked: dict[str, dict] = {}  # agent_id → {revoked_at, reason}
        self._blanket_active: bool = False
        self._loaded = False
        # PR-11: sync metadata
        self._server_version: Optional[int] = None
        self._last_synced_at: Optional[float] = None
        self._last_sync_failure: Optional[str] = None
        self._sync_failure_count: int = 0

    def _path(self) -> str:
        return os.path.join(self._dir, _REVOCATION_FILE)

    def load_from_disk(self) -> None:
        """Load persisted revocations from disk."""
        path = self._path()
        if not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                self._revoked = data.get("revoked", {})
                self._blanket_active = data.get("blanket_active", False)
                self._loaded = True
        except Exception:
            pass  # Corrupt file — start fresh

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load_from_disk()
            self._loaded = True

    def is_revoked(self, agent_id: str) -> bool:
        self._ensure_loaded()
        with self._lock:
            if self._blanket_active:
                return True
            entry = self._revoked.get(agent_id)
            if not entry:
                return False
            # Check expiry
            if (time.time() - entry.get("revoked_at", 0)) > _REVOCATION_EXPIRY:
                del self._revoked[agent_id]
                return False
            return True

    def revoke(self, agent_id: str, reason: str = "kill_switch") -> None:
        self._ensure_loaded()
        with self._lock:
            self._revoked[agent_id] = {
                "revoked_at": time.time(),
                "reason": reason,
            }
        self._persist()

    def set_blanket_kill(self, active: bool, reason: str = "") -> None:
        with self._lock:
            self._blanket_active = active
        self._persist()

    def clear_agent(self, agent_id: str) -> None:
        with self._lock:
            self._revoked.pop(agent_id, None)
        self._persist()

    def _persist(self) -> None:
        """Save to disk (best-effort, atomic rename)."""
        try:
            os.makedirs(self._dir, exist_ok=True)
            path = self._path()
            tmp = path + ".tmp"
            with self._lock:
                data = {
                    "revoked": dict(self._revoked),
                    "blanket_active": self._blanket_active,
                    "updated_at": time.time(),
                    "server_version": self._server_version,
                    "last_synced_at": self._last_synced_at,
                }
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception:
            pass  # Persistence failure is non-fatal

    # ── PR-11: Server sync API ─────────────────────────────────────────────────

    def get_server_version(self) -> Optional[int]:
        """Return the last known server revocation version (None if never synced)."""
        with self._lock:
            return self._server_version

    def apply_server_state(self, state: dict) -> None:
        """Atomically replace local revocation state from a server state payload.

        This is called by the background sync worker after a full-state fetch.
        Replaces the entire revocation set and blanket flag atomically.

        Args:
            state: Server response from GET /api/v1/sdk/revocations/state
                   Fields: version, blanket_kill_active, revoked_agents (list[str])
        """
        server_version = state.get("version")
        blanket = bool(state.get("blanket_kill_active", False))
        revoked_ids = state.get("revoked_agents", [])
        now = time.time()

        with self._lock:
            # Replace entire set (full-state sync — correctness over delta)
            self._revoked = {
                agent_id: {"revoked_at": now, "reason": "server_sync"}
                for agent_id in revoked_ids
            }
            self._blanket_active = blanket
            self._server_version = server_version
            self._last_synced_at = now
            self._last_sync_failure = None
            self._loaded = True

        # Persist the updated state atomically
        self._persist()

    def record_sync_failure(self, error: str) -> None:
        """Record a sync failure for diagnostics (does not alter revocation state)."""
        with self._lock:
            self._last_sync_failure = error
            self._sync_failure_count += 1

    def is_sync_stale(self, threshold_seconds: int) -> bool:
        """Return True if the last successful sync was more than threshold_seconds ago.

        Returns True if never synced and threshold > 0 (initial state is stale).
        If threshold_seconds <= 0, staleness checking is disabled.
        """
        if threshold_seconds <= 0:
            return False
        with self._lock:
            if self._last_synced_at is None:
                return True
            return (time.time() - self._last_synced_at) > threshold_seconds

    def get_diagnostics(self) -> dict:
        """Return sync diagnostics for observability. Never raises."""
        with self._lock:
            return {
                "server_version": self._server_version,
                "last_synced_at": self._last_synced_at,
                "last_sync_failure": self._last_sync_failure,
                "sync_failure_count": self._sync_failure_count,
                "blanket_kill_active": self._blanket_active,
                "revoked_count": len(self._revoked),
                "loaded_from_disk": self._loaded,
            }


# Module-level singleton
_cache = LocalRevocationCache()


def get_revocation_cache() -> LocalRevocationCache:
    return _cache
