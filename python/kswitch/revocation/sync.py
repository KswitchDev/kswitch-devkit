"""
Revocation sync worker — background polling to keep local revocation cache current.

PR-11 (Revocation Sync): Closes the gap where a long-running Python SDK process
could issue local ALLOW for a kill-switched agent because the LocalRevocationCache
was only populated at startup (disk load) with no live update path.

Architecture:
  - Background daemon thread polls GET /api/v1/sdk/revocations/version on interval
  - If server version changed: fetches GET /api/v1/sdk/revocations/state
  - Atomically applies full state to LocalRevocationCache (atomic disk rename)
  - Decision path continues using O(1) local lookup — no sync latency on hot path
  - Sync happens entirely in background; tool invocations are never blocked

Stale-sync behavior (Phase 5):
  Configurable via KSWITCH_REVOCATION_STALE_MODE:
    warn        — log warning, local decisions continue (default; suitable for dev/test)
    deny        — all local decisions forced to DENY until sync recovers (strict mode)
    conditional — all local decisions return "conditional" to force server escalation

Observability (Phase 6):
  - Startup logging
  - Per-poll success/failure logging
  - diagnostics() method returns full sync status
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("kswitch.revocation.sync")

# Sync worker state sentinel
_SENTINEL = object()


class RevocationSyncWorker:
    """Background worker that keeps the local revocation cache current.

    Usage:
        worker = RevocationSyncWorker(
            http_client=httpx_client,
            base_url="https://kswitch.internal:5001",
            interval=30,
        )
        worker.start()
        # ... process runs ...
        worker.stop()

    The worker runs as a daemon thread and stops automatically when the
    main process exits. Call stop() for clean shutdown.
    """

    VERSION_PATH = "/api/v1/sdk/revocations/version"
    STATE_PATH = "/api/v1/sdk/revocations/state"

    def __init__(
        self,
        http_client: Any,  # httpx.Client or compatible — any object with .get(url, **kwargs)
        base_url: str,
        interval: int = 30,
        stale_threshold: int = 150,
        stale_mode: str = "warn",
        revocation_cache=None,  # Optional[LocalRevocationCache] — uses singleton if None
        auth_header: Optional[str] = None,  # "Bearer <token>" — revocation endpoints are authenticated
    ):
        """
        Args:
            http_client:       An httpx.Client (or compatible) to make HTTP calls.
            base_url:          KSwitch server base URL (e.g. "https://localhost:5001").
            interval:          Poll interval in seconds (default: 30).
            stale_threshold:   Seconds without sync before state is stale (default: 5× interval).
            stale_mode:        Behavior on stale: "warn" | "deny" | "conditional".
            revocation_cache:  LocalRevocationCache to update (uses module singleton if None).
            auth_header:       Authorization header value (e.g. "Bearer <token>").
                               Revocation endpoints are authenticated at the application layer
                               (PR-11 closure). If the http_client already carries auth headers
                               (e.g. a KSwitchClient._http instance with persistent headers),
                               this parameter may be omitted — the client headers will be sent.
        """
        self._http = http_client
        self._base_url = base_url.rstrip("/")
        self._auth_header = auth_header
        self._interval = max(1, interval)
        self._stale_threshold = stale_threshold
        self._stale_mode = stale_mode

        if revocation_cache is None:
            from .cache import get_revocation_cache
            self._cache = get_revocation_cache()
        else:
            self._cache = revocation_cache

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Diagnostics
        self._started_at: Optional[float] = None
        self._poll_count: int = 0
        self._fetch_count: int = 0
        self._last_poll_at: Optional[float] = None
        self._last_fetch_at: Optional[float] = None
        self._last_error: Optional[str] = None
        self._running: bool = False

    def start(self) -> None:
        """Start the background sync thread. Safe to call multiple times."""
        with self._lock:
            if self._running:
                return
            self._stop_event.clear()
            self._started_at = time.time()
            self._running = True
            self._thread = threading.Thread(
                target=self._run,
                name="kswitch-revocation-sync",
                daemon=True,
            )
            self._thread.start()
        logger.info(
            "kswitch.revocation.sync: started | interval=%ds stale_threshold=%ds stale_mode=%s",
            self._interval, self._stale_threshold, self._stale_mode,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the background sync thread gracefully."""
        with self._lock:
            if not self._running:
                return
            self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("kswitch.revocation.sync: stopped")

    def is_running(self) -> bool:
        return self._running

    def sync_once(self) -> bool:
        """Perform a single sync cycle synchronously (for tests / manual trigger).

        Returns True if a full-state fetch was performed, False if version unchanged.
        Raises on unrecoverable error.
        """
        return self._poll_and_maybe_fetch()

    def diagnostics(self) -> dict:
        """Return current sync worker status for observability."""
        cache_diag = self._cache.get_diagnostics()
        with self._lock:
            return {
                "sync_worker": {
                    "running": self._running,
                    "started_at": self._started_at,
                    "poll_count": self._poll_count,
                    "fetch_count": self._fetch_count,
                    "last_poll_at": self._last_poll_at,
                    "last_fetch_at": self._last_fetch_at,
                    "last_error": self._last_error,
                    "interval_seconds": self._interval,
                    "stale_threshold_seconds": self._stale_threshold,
                    "stale_mode": self._stale_mode,
                    "is_stale": self._cache.is_sync_stale(self._stale_threshold),
                },
                "cache": cache_diag,
            }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(self) -> None:
        """Main loop — runs in the background daemon thread."""
        logger.debug("kswitch.revocation.sync: thread started")
        while not self._stop_event.is_set():
            try:
                self._poll_and_maybe_fetch()
            except Exception as exc:
                # Non-fatal — log and continue
                err = str(exc)[:120]
                self._last_error = err
                self._cache.record_sync_failure(err)
                logger.warning("kswitch.revocation.sync: poll error: %s", err)
            # Sleep in short increments so stop_event is checked promptly
            for _ in range(self._interval * 10):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)
        logger.debug("kswitch.revocation.sync: thread exiting")

    def _poll_and_maybe_fetch(self) -> bool:
        """Poll version endpoint. Fetch full state if version changed.

        Returns True if a full-state fetch was performed.
        """
        now = time.time()
        self._poll_count += 1
        self._last_poll_at = now

        # ── Step 1: Cheap version check ────────────────────────────────────────
        version_url = self._base_url + self.VERSION_PATH
        _extra_headers: dict = {}
        if self._auth_header:
            _extra_headers["Authorization"] = self._auth_header
        try:
            resp = self._http.get(version_url, timeout=5.0,
                                  **({"headers": _extra_headers} if _extra_headers else {}))
            if resp.status_code == 401:
                err = "revocation_version_auth_failed: HTTP 401 — check auth_header or SDK token config"
                self._last_error = err
                self._cache.record_sync_failure(err)
                logger.error("kswitch.revocation.sync: %s", err)
                return False
            resp.raise_for_status()
            version_data = resp.json()
        except Exception as exc:
            err = f"version_check_failed: {exc!s:.80}"
            self._last_error = err
            self._cache.record_sync_failure(err)
            logger.warning("kswitch.revocation.sync: version check failed: %s", err)
            self._check_stale_behavior()
            return False

        server_version = version_data.get("version")
        blanket = version_data.get("blanket_kill_active", False)

        # ── Step 2: Blanket kill fast path ─────────────────────────────────────
        # If blanket_kill_active flipped on, apply immediately without waiting
        # for the full-state fetch (blanket kill is the highest-priority signal).
        if blanket:
            cached_diag = self._cache.get_diagnostics()
            if not cached_diag.get("blanket_kill_active"):
                logger.critical(
                    "kswitch.revocation.sync: BLANKET KILL ACTIVE — applying immediately"
                )
                self._cache.apply_server_state({
                    "version": server_version,
                    "blanket_kill_active": True,
                    "revoked_agents": [],
                })
                return True

        # ── Step 3: Version comparison ─────────────────────────────────────────
        local_version = self._cache.get_server_version()
        if local_version is not None and local_version == server_version:
            # No change — nothing to do
            logger.debug(
                "kswitch.revocation.sync: version unchanged (%s) — skip fetch",
                server_version,
            )
            # Update last_synced_at so staleness clock resets even on no-op polls
            with self._cache._lock:
                self._cache._last_synced_at = time.time()
            return False

        # ── Step 4: Full-state fetch ───────────────────────────────────────────
        logger.info(
            "kswitch.revocation.sync: version changed %s→%s — fetching full state",
            local_version, server_version,
        )
        state_url = self._base_url + self.STATE_PATH
        try:
            state_resp = self._http.get(state_url, timeout=10.0,
                                        **({"headers": _extra_headers} if _extra_headers else {}))
            if state_resp.status_code == 401:
                err = "revocation_state_auth_failed: HTTP 401 — check auth_header or SDK token config"
                self._last_error = err
                self._cache.record_sync_failure(err)
                logger.error("kswitch.revocation.sync: %s", err)
                return False
            state_resp.raise_for_status()
            state = state_resp.json()
        except Exception as exc:
            err = f"state_fetch_failed: {exc!s:.80}"
            self._last_error = err
            self._cache.record_sync_failure(err)
            logger.error("kswitch.revocation.sync: state fetch failed: %s", err)
            return False

        # ── Step 5: Atomic cache update ────────────────────────────────────────
        self._cache.apply_server_state(state)
        self._fetch_count += 1
        self._last_fetch_at = time.time()
        self._last_error = None

        logger.info(
            "kswitch.revocation.sync: synced ok | version=%s blanket=%s revoked=%d",
            state.get("version"),
            state.get("blanket_kill_active"),
            len(state.get("revoked_agents", [])),
        )
        return True

    def _check_stale_behavior(self) -> None:
        """Apply stale-sync policy if revocation state is stale.

        Called after a sync failure to enforce the configured stale_mode.
        The stale mode does not alter the cache — it is checked at decision time
        by the LocalPDPEvaluator via is_stale_for_decision().
        """
        if not self._cache.is_sync_stale(self._stale_threshold):
            return
        if self._stale_mode == "warn":
            logger.warning(
                "kswitch.revocation.sync: STALE — revocation state has not synced "
                "for >%ds (stale_mode=warn, decisions continue with cached state)",
                self._stale_threshold,
            )
        elif self._stale_mode == "deny":
            logger.error(
                "kswitch.revocation.sync: STALE — stale_mode=deny, all decisions "
                "will be DENIED until sync recovers"
            )
        elif self._stale_mode == "conditional":
            logger.warning(
                "kswitch.revocation.sync: STALE — stale_mode=conditional, all "
                "decisions will escalate to server until sync recovers"
            )


# ── Module-level singleton worker (lifecycle managed by KSwitchRuntime) ───────

_worker: Optional[RevocationSyncWorker] = None
_worker_lock = threading.Lock()


def get_sync_worker() -> Optional[RevocationSyncWorker]:
    """Return the active sync worker, or None if not started."""
    return _worker


def start_sync_worker(
    http_client: Any,
    base_url: str,
    interval: int = 30,
    stale_threshold: int = 150,
    stale_mode: str = "warn",
    auth_header: Optional[str] = None,
) -> RevocationSyncWorker:
    """Start (or return existing) module-level sync worker.

    Idempotent — safe to call multiple times. Returns the running worker.
    auth_header: "Bearer <token>" for revocation endpoint authentication (PR-11 closure).
    """
    global _worker
    with _worker_lock:
        if _worker is not None and _worker.is_running():
            return _worker
        _worker = RevocationSyncWorker(
            http_client=http_client,
            base_url=base_url,
            interval=interval,
            stale_threshold=stale_threshold,
            stale_mode=stale_mode,
            auth_header=auth_header,
        )
        _worker.start()
        return _worker


def stop_sync_worker() -> None:
    """Stop the module-level sync worker if running."""
    global _worker
    with _worker_lock:
        if _worker is not None:
            _worker.stop()
            _worker = None
