"""
Tests for the revocation sync worker (PR-11).

Covers:
- Version unchanged → no full-state fetch
- Version changed → full-state fetch occurs
- Cache file updated atomically
- In-memory cache updated
- Sync failure logged
- Stale sync detection
- Diagnostics output
- Blanket kill fast path
"""
import json
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, call
from unittest.mock import PropertyMock


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_http_client(version_resp=None, state_resp=None):
    """Create a mock httpx-compatible client."""
    client = MagicMock()
    v_resp = MagicMock()
    v_resp.raise_for_status.return_value = None
    v_resp.json.return_value = version_resp or {"version": 1, "generated_at": "2026-01-01T00:00:00Z", "blanket_kill_active": False}

    s_resp = MagicMock()
    s_resp.raise_for_status.return_value = None
    s_resp.json.return_value = state_resp or {
        "version": 1,
        "generated_at": "2026-01-01T00:00:00Z",
        "blanket_kill_active": False,
        "revoked_agents": [],
    }

    def _get_side_effect(url, **kwargs):
        if "/version" in url:
            return v_resp
        return s_resp

    client.get.side_effect = _get_side_effect
    return client, v_resp, s_resp


def _make_cache(tmpdir):
    """Create a fresh LocalRevocationCache backed by a temp directory."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))
    from kswitch.revocation.cache import LocalRevocationCache
    return LocalRevocationCache(revocation_dir=tmpdir)


def _make_worker(http_client, cache, base_url="https://test.local:5001", interval=30):
    from kswitch.revocation.sync import RevocationSyncWorker
    return RevocationSyncWorker(
        http_client=http_client,
        base_url=base_url,
        interval=interval,
        stale_threshold=interval * 5,
        stale_mode="warn",
        revocation_cache=cache,
    )


# ── Test suite ────────────────────────────────────────────────────────────────

class TestVersionUnchangedNoFetch(unittest.TestCase):
    """Version unchanged → only version endpoint called, no state fetch."""

    def test_no_fetch_when_version_same(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            # Pre-set server version so it matches what mock returns
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            http, v_resp, s_resp = _make_http_client(
                version_resp={"version": 1, "generated_at": "2026-01-01T00:00:00Z", "blanket_kill_active": False}
            )
            worker = _make_worker(http, cache)
            result = worker.sync_once()

        self.assertFalse(result)
        # Only the version endpoint was called, not the state endpoint
        for c in http.get.call_args_list:
            url = c[0][0]
            self.assertNotIn("/state", url)


class TestVersionChangedFetchOccurs(unittest.TestCase):
    """Version changed → full state fetch is triggered."""

    def test_fetch_on_version_change(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            # Cache starts at version 1
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            # Server now reports version 2 with a revoked agent
            http, _, _ = _make_http_client(
                version_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z", "blanket_kill_active": False},
                state_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z",
                            "blanket_kill_active": False, "revoked_agents": ["agent:bad-actor@test"]},
            )
            worker = _make_worker(http, cache)
            result = worker.sync_once()

        self.assertTrue(result)
        # State endpoint was called
        state_calls = [c for c in http.get.call_args_list if "/state" in c[0][0]]
        self.assertGreater(len(state_calls), 0)

    def test_revoked_agent_in_cache_after_fetch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            http, _, _ = _make_http_client(
                version_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z", "blanket_kill_active": False},
                state_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z",
                            "blanket_kill_active": False, "revoked_agents": ["agent:kill-me@test"]},
            )
            worker = _make_worker(http, cache)
            worker.sync_once()

        self.assertTrue(cache.is_revoked("agent:kill-me@test"))
        self.assertFalse(cache.is_revoked("agent:innocent@test"))


class TestCacheFileUpdatedAtomically(unittest.TestCase):
    """After sync, the disk cache file reflects the new state."""

    def test_disk_file_updated_after_sync(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            http, _, _ = _make_http_client(
                version_resp={"version": 5, "generated_at": "2026-01-01T00:05:00Z", "blanket_kill_active": False},
                state_resp={"version": 5, "generated_at": "2026-01-01T00:05:00Z",
                            "blanket_kill_active": False, "revoked_agents": ["agent:disk-test@corp"]},
            )
            worker = _make_worker(http, cache)
            worker.sync_once()

            # Read disk directly
            disk_path = os.path.join(tmpdir, "revoked.json")
            self.assertTrue(os.path.exists(disk_path))
            with open(disk_path) as f:
                data = json.load(f)

        # Agent should appear in the disk file
        self.assertIn("agent:disk-test@corp", data.get("revoked", {}))
        self.assertEqual(data.get("server_version"), 5)

    def test_no_tmp_file_left_behind(self):
        """Atomic rename: .tmp file must not persist after sync."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            http, _, _ = _make_http_client(
                version_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z", "blanket_kill_active": False},
                state_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z",
                            "blanket_kill_active": False, "revoked_agents": []},
            )
            worker = _make_worker(http, cache)
            worker.sync_once()

            tmp_path = os.path.join(tmpdir, "revoked.json.tmp")
        self.assertFalse(os.path.exists(tmp_path))


class TestInMemoryCacheUpdated(unittest.TestCase):
    """In-memory state reflects server state after sync."""

    def test_server_version_tracked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            http, _, _ = _make_http_client(
                version_resp={"version": 7, "generated_at": "2026-01-01T00:07:00Z", "blanket_kill_active": False},
                state_resp={"version": 7, "generated_at": "2026-01-01T00:07:00Z",
                            "blanket_kill_active": False, "revoked_agents": []},
            )
            worker = _make_worker(http, cache)
            worker.sync_once()

        self.assertEqual(cache.get_server_version(), 7)

    def test_blanket_kill_applied(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            http, _, _ = _make_http_client(
                version_resp={"version": 3, "generated_at": "2026-01-01T00:03:00Z", "blanket_kill_active": True},
                state_resp={"version": 3, "generated_at": "2026-01-01T00:03:00Z",
                            "blanket_kill_active": True, "revoked_agents": []},
            )
            worker = _make_worker(http, cache)
            worker.sync_once()

        # Any agent should be revoked under blanket kill
        self.assertTrue(cache.is_revoked("agent:anyone@corp"))

    def test_last_synced_at_set(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            http, _, _ = _make_http_client(
                version_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z", "blanket_kill_active": False},
                state_resp={"version": 2, "generated_at": "2026-01-01T00:01:00Z",
                            "blanket_kill_active": False, "revoked_agents": []},
            )
            before = time.time()
            worker = _make_worker(http, cache)
            worker.sync_once()
            after = time.time()

        diag = cache.get_diagnostics()
        self.assertIsNotNone(diag["last_synced_at"])
        self.assertGreaterEqual(diag["last_synced_at"], before)
        self.assertLessEqual(diag["last_synced_at"], after)


class TestSyncFailureHandling(unittest.TestCase):
    """Sync failures are recorded, cache state preserved."""

    def test_version_check_failure_recorded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            # Seed some prior revocations
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": ["agent:prior@corp"]})

            http = MagicMock()
            http.get.side_effect = ConnectionError("server unreachable")
            worker = _make_worker(http, cache)
            result = worker.sync_once()

        self.assertFalse(result)
        diag = cache.get_diagnostics()
        self.assertIsNotNone(diag["last_sync_failure"])
        self.assertIn("server unreachable", diag["last_sync_failure"])

    def test_prior_revocations_preserved_on_failure(self):
        """A sync failure must NOT clear existing revocations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": ["agent:stay-revoked@corp"]})

            http = MagicMock()
            http.get.side_effect = ConnectionError("network down")
            worker = _make_worker(http, cache)
            worker.sync_once()

        # Prior revocations must survive sync failure
        self.assertTrue(cache.is_revoked("agent:stay-revoked@corp"))

    def test_state_fetch_failure_recorded(self):
        """State fetch failure after version check is recorded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            v_resp = MagicMock()
            v_resp.raise_for_status.return_value = None
            v_resp.json.return_value = {"version": 2, "generated_at": "2026-01-01T00:01:00Z", "blanket_kill_active": False}

            s_resp = MagicMock()
            s_resp.raise_for_status.side_effect = Exception("state endpoint 503")

            def _side(url, **kwargs):
                if "/version" in url:
                    return v_resp
                return s_resp

            http = MagicMock()
            http.get.side_effect = _side

            worker = _make_worker(http, cache)
            result = worker.sync_once()

        self.assertFalse(result)
        diag = cache.get_diagnostics()
        self.assertIsNotNone(diag["last_sync_failure"])


class TestStaleSyncDetection(unittest.TestCase):
    """Stale sync detection via is_sync_stale()."""

    def test_never_synced_is_stale(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            # No sync ever performed
            self.assertTrue(cache.is_sync_stale(threshold_seconds=30))

    def test_recently_synced_not_stale(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})
            self.assertFalse(cache.is_sync_stale(threshold_seconds=30))

    def test_old_sync_is_stale(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            # Manually set last_synced_at to 300 seconds ago
            with cache._lock:
                cache._last_synced_at = time.time() - 400
            self.assertTrue(cache.is_sync_stale(threshold_seconds=300))

    def test_zero_threshold_never_stale(self):
        """threshold_seconds=0 disables staleness checking."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            self.assertFalse(cache.is_sync_stale(threshold_seconds=0))


class TestDiagnosticsOutput(unittest.TestCase):
    """Diagnostics include all required fields."""

    def test_worker_diagnostics_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            http, _, _ = _make_http_client()
            worker = _make_worker(http, cache)
            diag = worker.diagnostics()

        self.assertIn("sync_worker", diag)
        self.assertIn("cache", diag)

        sw = diag["sync_worker"]
        self.assertIn("running", sw)
        self.assertIn("poll_count", sw)
        self.assertIn("fetch_count", sw)
        self.assertIn("last_poll_at", sw)
        self.assertIn("last_fetch_at", sw)
        self.assertIn("last_error", sw)
        self.assertIn("interval_seconds", sw)
        self.assertIn("stale_threshold_seconds", sw)
        self.assertIn("stale_mode", sw)
        self.assertIn("is_stale", sw)

    def test_cache_diagnostics_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            diag = cache.get_diagnostics()

        self.assertIn("server_version", diag)
        self.assertIn("last_synced_at", diag)
        self.assertIn("last_sync_failure", diag)
        self.assertIn("sync_failure_count", diag)
        self.assertIn("blanket_kill_active", diag)
        self.assertIn("revoked_count", diag)


class TestBlanketKillFastPath(unittest.TestCase):
    """Blanket kill in version response triggers immediate cache update."""

    def test_blanket_kill_fast_path(self):
        """If blanket_kill_active appears in version check, apply immediately."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            # Start with blanket kill NOT active
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})
            self.assertFalse(cache.is_revoked("agent:any@corp"))

            # Server version check shows blanket_kill_active=True
            v_resp = MagicMock()
            v_resp.raise_for_status.return_value = None
            v_resp.json.return_value = {"version": 2, "generated_at": "2026-01-01T00:01:00Z", "blanket_kill_active": True}

            s_resp = MagicMock()
            s_resp.raise_for_status.return_value = None
            s_resp.json.return_value = {"version": 2, "blanket_kill_active": True, "revoked_agents": []}

            def _side(url, **kwargs):
                if "/version" in url:
                    return v_resp
                return s_resp

            http = MagicMock()
            http.get.side_effect = _side
            worker = _make_worker(http, cache)
            worker.sync_once()

        self.assertTrue(cache.is_revoked("agent:any@corp"))


if __name__ == "__main__":
    unittest.main()
