"""Tests for AuditSender — PR-12 async central audit forwarding."""
import json
import os
import queue
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

from kswitch.audit.sender import AuditSender, start_audit_sender, stop_audit_sender, get_audit_sender
from kswitch.audit.emitter import AuditEmitter


def _make_http_client(status_code=200):
    """Return a mock httpx-like client that returns the given status code."""
    response = MagicMock()
    response.status_code = status_code
    client = MagicMock()
    client.post.return_value = response
    return client


def _make_event(n=1):
    return {"agent_id": f"agent:test-{n}@bank.internal", "allowed": True, "event_type": "enforcement.allow"}


class TestAuditSenderBatchSend:
    def test_enqueue_and_batch_send_success(self):
        """Enqueue 3 events, flush, assert POST called with batch."""
        http = _make_http_client(200)
        sender = AuditSender(
            http_client=http,
            ingest_url="https://localhost:5001/api/v1/sdk/audit/events",
            batch_size=10,
            flush_interval=1,
        )
        sender.start()
        try:
            for i in range(3):
                sender.enqueue(_make_event(i))
            # Wait for flush (interval=1s)
            time.sleep(1.5)
        finally:
            sender.stop(timeout=3.0)

        assert http.post.called
        call_args = http.post.call_args
        body = json.loads(call_args.kwargs.get("content") or call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs["content"])
        assert "events" in body
        assert len(body["events"]) == 3

    def test_failed_send_retries(self):
        """Mock POST fails first 2 times, succeeds 3rd — assert 3 calls."""
        response_fail = MagicMock()
        response_fail.status_code = 500
        response_ok = MagicMock()
        response_ok.status_code = 200

        http = MagicMock()
        http.post.side_effect = [response_fail, response_fail, response_ok]

        sender = AuditSender(
            http_client=http,
            ingest_url="https://localhost:5001/api/v1/sdk/audit/events",
            batch_size=1,
            flush_interval=1,
            max_retries=5,
        )
        # Call _backoff_send directly to avoid sleep delays in test
        batch = [_make_event(1)]
        # Patch time.sleep to avoid actual waiting
        with patch("kswitch.audit.sender.time.sleep"):
            result = sender._backoff_send(batch)

        assert result is True
        assert http.post.call_count == 3

    def test_max_retries_drops_batch(self):
        """POST always fails — assert fail_count incremented after max retries."""
        response_fail = MagicMock()
        response_fail.status_code = 503
        http = MagicMock()
        http.post.return_value = response_fail

        sender = AuditSender(
            http_client=http,
            ingest_url="https://localhost:5001/api/v1/sdk/audit/events",
            batch_size=1,
            flush_interval=1,
            max_retries=3,
        )
        batch = [_make_event(1), _make_event(2)]
        with patch("kswitch.audit.sender.time.sleep"):
            result = sender._backoff_send(batch)

        assert result is False
        diag = sender.diagnostics()
        assert diag["fail_count"] == 2  # 2 events in batch


class TestAuditSenderDiagnostics:
    def test_sender_diagnostics_fields(self):
        """Start sender, check all 8 required fields present."""
        http = _make_http_client(200)
        sender = AuditSender(
            http_client=http,
            ingest_url="https://localhost:5001/api/v1/sdk/audit/events",
        )
        sender.start()
        try:
            diag = sender.diagnostics()
            required = {
                "forwarding_enabled", "running", "queue_depth",
                "last_send_at", "last_failure", "send_count", "fail_count", "drop_count"
            }
            assert required == set(diag.keys()), f"Missing fields: {required - set(diag.keys())}"
            assert diag["forwarding_enabled"] is True
            assert diag["running"] is True
        finally:
            sender.stop()


class TestAuditSenderQueueFull:
    def test_queue_full_increments_drop_count(self):
        """Fill queue to max, enqueue one more, assert drop_count=1."""
        http = _make_http_client(200)
        # Very small queue for test
        sender = AuditSender(
            http_client=http,
            ingest_url="https://localhost:5001/api/v1/sdk/audit/events",
        )
        # Fill the queue manually
        for _ in range(sender._queue.maxsize):
            try:
                sender._queue.put_nowait(_make_event())
            except queue.Full:
                break

        # Now enqueue one more — should be dropped
        sender.enqueue(_make_event(999))
        assert sender.diagnostics()["drop_count"] == 1


class TestAuditSenderLifecycle:
    def test_sender_starts_and_stops(self):
        """Start/stop cycle: is_running() transitions correctly."""
        http = _make_http_client(200)
        sender = AuditSender(
            http_client=http,
            ingest_url="https://localhost:5001/api/v1/sdk/audit/events",
        )
        assert sender.is_running() is False
        sender.start()
        assert sender.is_running() is True
        sender.stop(timeout=3.0)
        assert sender.is_running() is False


class TestAuditSenderNonBlocking:
    def test_decision_not_blocked_on_send_failure(self, tmp_path):
        """With sender throwing on enqueue, emit() still returns quickly."""
        bad_sender = MagicMock()
        bad_sender.enqueue.side_effect = RuntimeError("network exploded")

        emitter = AuditEmitter(audit_dir=str(tmp_path))
        emitter.set_sender(bad_sender)

        start = time.time()
        emitter.emit({"event_type": "enforcement.allow", "agent_id": "x", "allowed": True})
        elapsed = time.time() - start

        # Must return fast — well under 1 second
        assert elapsed < 1.0

    def test_jsonl_still_written_when_server_fails(self, tmp_path):
        """Server POST fails, but JSONL file still has the event."""
        http = _make_http_client(500)
        sender = AuditSender(
            http_client=http,
            ingest_url="https://localhost:5001/api/v1/sdk/audit/events",
            max_retries=0,
        )
        emitter = AuditEmitter(audit_dir=str(tmp_path))
        emitter.set_sender(sender)

        event = {"event_type": "enforcement.allow", "agent_id": "agent:x@y", "allowed": True}
        emitter.emit(event)

        events_path = os.path.join(str(tmp_path), "events.jsonl")
        assert os.path.exists(events_path)
        with open(events_path) as f:
            written = json.loads(f.readline())
        assert written["agent_id"] == "agent:x@y"
