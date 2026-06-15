"""Context-pack invalidation sync worker.

EP-011 T3: authenticated HTTP polling for context-pack invalidation deltas.
This deliberately reuses the KSwitch API/client auth boundary instead of
connecting SDKs directly to Redis/Valkey or another broker.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("kswitch.context.invalidation_sync")


class ContextInvalidationSyncWorker:
    """Background worker that evicts stale local context packs."""

    VERSION_PATH = "/api/v1/sdk/context-invalidations/version"
    EVENTS_PATH = "/api/v1/sdk/context-invalidations/events"

    def __init__(
        self,
        http_client: Any,
        base_url: str,
        interval: int = 30,
        context_cache: Any = None,
        auth_header: Optional[str] = None,
    ):
        self._http = http_client
        self._base_url = base_url.rstrip("/")
        self._interval = max(1, interval)
        self._auth_header = auth_header
        if context_cache is None:
            from .local_cache import get_context_cache
            self._cache = get_context_cache()
        else:
            self._cache = context_cache

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self._running = False
        self._started_at: Optional[float] = None
        self._last_version: int = 0
        self._poll_count = 0
        self._fetch_count = 0
        self._invalidate_count = 0
        self._last_poll_at: Optional[float] = None
        self._last_fetch_at: Optional[float] = None
        self._last_error: Optional[str] = None
        self._last_compacted = False

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._stop_event.clear()
            self._started_at = time.time()
            self._running = True
            self._thread = threading.Thread(
                target=self._run,
                name="kswitch-context-invalidation-sync",
                daemon=True,
            )
            self._thread.start()
        logger.info("kswitch.context.invalidation_sync: started | interval=%ds", self._interval)

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("kswitch.context.invalidation_sync: stopped")

    def is_running(self) -> bool:
        return self._running

    def sync_once(self) -> int:
        """Run one poll/fetch cycle. Returns number of subject evictions."""
        return self._poll_and_maybe_fetch()

    def diagnostics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "started_at": self._started_at,
                "last_version": self._last_version,
                "poll_count": self._poll_count,
                "fetch_count": self._fetch_count,
                "invalidate_count": self._invalidate_count,
                "last_poll_at": self._last_poll_at,
                "last_fetch_at": self._last_fetch_at,
                "last_error": self._last_error,
                "last_compacted": self._last_compacted,
                "interval_seconds": self._interval,
            }

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll_and_maybe_fetch()
            except Exception as exc:
                self._last_error = str(exc)[:120]
                logger.warning("kswitch.context.invalidation_sync: poll error: %s", self._last_error)
            for _ in range(self._interval * 10):
                if self._stop_event.is_set():
                    break
                time.sleep(0.1)

    def _headers(self) -> dict[str, str]:
        if not self._auth_header:
            return {}
        return {"Authorization": self._auth_header}

    def _poll_and_maybe_fetch(self) -> int:
        self._poll_count += 1
        self._last_poll_at = time.time()
        request_kwargs = {"headers": self._headers()} if self._auth_header else {}

        version_resp = self._http.get(
            self._base_url + self.VERSION_PATH,
            timeout=5.0,
            **request_kwargs,
        )
        if version_resp.status_code == 401:
            self._last_error = "context_invalidation_version_auth_failed"
            logger.error("kswitch.context.invalidation_sync: %s", self._last_error)
            return 0
        version_resp.raise_for_status()
        version_data = version_resp.json()
        server_version = int(version_data.get("version") or 0)
        if server_version < self._last_version:
            self._cache.invalidate(None, remove_disk=True)
            self._last_compacted = True
            self._last_version = server_version
            self._last_error = None
            logger.warning(
                "kswitch.context.invalidation_sync: server version regressed; flushed local context cache"
            )
            return 0
        if server_version <= self._last_version:
            self._last_error = None
            return 0

        events_url = f"{self._base_url}{self.EVENTS_PATH}?since={self._last_version}&limit=1000"
        events_resp = self._http.get(events_url, timeout=10.0, **request_kwargs)
        if events_resp.status_code == 401:
            self._last_error = "context_invalidation_events_auth_failed"
            logger.error("kswitch.context.invalidation_sync: %s", self._last_error)
            return 0
        events_resp.raise_for_status()
        payload = events_resp.json()
        self._fetch_count += 1
        self._last_fetch_at = time.time()

        if bool(payload.get("compacted")):
            self._cache.invalidate(None, remove_disk=True)
            self._last_compacted = True
            self._last_version = int(payload.get("version") or server_version)
            self._last_error = None
            return 0

        self._last_compacted = False
        invalidated = 0
        seen: set[str] = set()
        for event in payload.get("events") or []:
            subject_id = str(event.get("subject_id") or "")
            if not subject_id or subject_id in seen:
                continue
            seen.add(subject_id)
            self._cache.invalidate(subject_id, remove_disk=True)
            invalidated += 1
        self._invalidate_count += invalidated
        self._last_version = int(payload.get("returned_version") or payload.get("version") or server_version)
        self._last_error = None
        return invalidated


_worker: Optional[ContextInvalidationSyncWorker] = None
_worker_lock = threading.Lock()


def get_invalidation_sync_worker() -> Optional[ContextInvalidationSyncWorker]:
    return _worker


def start_invalidation_sync_worker(
    http_client: Any,
    base_url: str,
    interval: int = 30,
    auth_header: Optional[str] = None,
) -> ContextInvalidationSyncWorker:
    global _worker
    with _worker_lock:
        if _worker is not None and _worker.is_running():
            return _worker
        _worker = ContextInvalidationSyncWorker(
            http_client=http_client,
            base_url=base_url,
            interval=interval,
            auth_header=auth_header,
        )
        _worker.start()
        return _worker


def stop_invalidation_sync_worker(timeout: float = 5.0) -> None:
    global _worker
    with _worker_lock:
        if _worker is None:
            return
        _worker.stop(timeout=timeout)
        _worker = None
