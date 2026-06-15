"""
AuditSender — async background sender for central audit forwarding (PR-12).

Architecture:
  AuditEmitter.emit() → JSONL (local, immediate)
                      → AuditSender.enqueue() (async, non-blocking)
                            ↓ in-memory queue
                       background thread → POST /api/v1/sdk/audit/events
                                        → enforcement_audit_events DB table

Retry policy: exponential backoff (1s → 2s → 4s → ... → 60s cap), max 5 retries.
After max retries: event dropped, drop_count incremented, failure logged.

Decision path is never blocked — emit() returns after JSONL write.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

_QUEUE_MAXSIZE = 500


class AuditSender:
    """Background sender that batches SDK audit events to the central server."""

    def __init__(
        self,
        http_client: Any,
        ingest_url: str,
        batch_size: int = 10,
        flush_interval: int = 5,
        max_retries: int = 5,
    ):
        self._http_client = http_client
        self._ingest_url = ingest_url
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_retries = max_retries

        self._queue: queue.Queue = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._thread: Optional[threading.Thread] = None
        self._running = False

        # Diagnostics counters
        self._send_count = 0
        self._fail_count = 0
        self._drop_count = 0
        self._last_send_at: Optional[float] = None
        self._last_failure: Optional[str] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background sender daemon thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._run,
                daemon=True,
                name="kswitch-audit-sender",
            )
            self._thread.start()
            logger.debug("AuditSender started (url=%s, batch=%d, interval=%ds)",
                         self._ingest_url, self._batch_size, self._flush_interval)

    def stop(self, timeout: float = 5.0) -> None:
        """Signal stop, drain remaining events, and wait for thread to exit."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        """Return True if the background thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def enqueue(self, event: dict) -> None:
        """Enqueue an event for background forwarding. Non-blocking.

        If the queue is full the event is silently dropped and drop_count is incremented.
        """
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._lock:
                self._drop_count += 1
            logger.warning("AuditSender queue full — dropping event (drop_count=%d)", self._drop_count)

    def diagnostics(self) -> dict:
        """Return current sender health stats."""
        with self._lock:
            return {
                "forwarding_enabled": True,
                "running": self.is_running(),
                "queue_depth": self._queue.qsize(),
                "last_send_at": self._last_send_at,
                "last_failure": self._last_failure,
                "send_count": self._send_count,
                "fail_count": self._fail_count,
                "drop_count": self._drop_count,
            }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(self) -> None:
        """Main loop: accumulate batch, flush on batch_size or flush_interval."""
        batch: list = []
        deadline = time.monotonic() + self._flush_interval

        while self._running or not self._queue.empty():
            now = time.monotonic()
            time_left = max(0.0, deadline - now)

            try:
                event = self._queue.get(timeout=min(time_left, 0.5))
                batch.append(event)
            except queue.Empty:
                pass

            should_flush = (
                len(batch) >= self._batch_size
                or (batch and time.monotonic() >= deadline)
            )
            if should_flush:
                self._backoff_send(batch)
                batch = []
                deadline = time.monotonic() + self._flush_interval

        # Final drain
        if batch:
            self._backoff_send(batch)

    def _send_batch(self, batch: list) -> bool:
        """POST a batch of events to the server. Returns True on 2xx."""
        try:
            payload = json.dumps({"events": batch}).encode("utf-8")
            response = self._http_client.post(
                self._ingest_url,
                content=payload,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code < 300:
                with self._lock:
                    self._send_count += len(batch)
                    self._last_send_at = time.time()
                return True
            else:
                with self._lock:
                    self._last_failure = f"HTTP {response.status_code}"
                return False
        except Exception as exc:
            with self._lock:
                self._last_failure = str(exc)
            return False

    def _backoff_send(self, batch: list) -> bool:
        """Retry batch with exponential backoff up to max_retries."""
        delay = 1.0
        for attempt in range(self._max_retries + 1):
            if self._send_batch(batch):
                return True
            if attempt < self._max_retries:
                time.sleep(min(delay, 60.0))
                delay *= 2
        # All retries exhausted
        with self._lock:
            self._fail_count += len(batch)
        logger.error(
            "AuditSender: batch of %d events dropped after %d retries (last_failure=%s)",
            len(batch), self._max_retries, self._last_failure,
        )
        return False


# ── Module-level singleton ────────────────────────────────────────────────────

_sender: Optional[AuditSender] = None
_sender_lock = threading.Lock()


def get_audit_sender() -> Optional[AuditSender]:
    """Return the active AuditSender singleton, or None if not started."""
    return _sender


def start_audit_sender(
    http_client: Any,
    ingest_url: str,
    batch_size: int = 10,
    flush_interval: int = 5,
    max_retries: int = 5,
) -> AuditSender:
    """Start (or return the existing running) AuditSender singleton."""
    global _sender
    with _sender_lock:
        if _sender is not None and _sender.is_running():
            return _sender
        _sender = AuditSender(
            http_client=http_client,
            ingest_url=ingest_url,
            batch_size=batch_size,
            flush_interval=flush_interval,
            max_retries=max_retries,
        )
        _sender.start()
        return _sender


def stop_audit_sender() -> None:
    """Stop and clear the AuditSender singleton."""
    global _sender
    with _sender_lock:
        if _sender is not None:
            _sender.stop()
            _sender = None
