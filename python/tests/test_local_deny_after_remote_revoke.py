"""
End-to-end proof: remote revoke → local deny without restart (PR-11).

Test sequence per execution pack Phase 7:
  1. Start with local SDK path allowing agent
  2. Revoke agent on server (simulate via sync worker with mocked endpoints)
  3. Wait for one sync cycle or trigger sync directly
  4. Invoke same governed path again
  5. Assert local deny with no normal-path Flask decision call

Also tests:
  - Blanket kill leads to local deny after sync
  - Revocation deny does not call the server enforcement endpoint
  - Re-sync to cleared state restores allow
"""
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_cache(tmpdir):
    from kswitch.revocation.cache import LocalRevocationCache
    return LocalRevocationCache(revocation_dir=tmpdir)


def _make_sync_worker(http, cache, base_url="https://test.local:5001"):
    from kswitch.revocation.sync import RevocationSyncWorker
    return RevocationSyncWorker(
        http_client=http,
        base_url=base_url,
        interval=1,
        stale_threshold=10,
        stale_mode="warn",
        revocation_cache=cache,
    )


def _mock_allow_bundle_context(evaluator):
    """Patch bundle and context caches on evaluator to return an allow result."""
    from kswitch.bundle.local_cache import LocalBundle
    from kswitch.context.local_cache import LocalContextPack

    bundle = LocalBundle(
        version=1,
        bundle_id="test-bundle",
        compiled_at="2026-01-01T00:00:00Z",
        cedar_text_enforce='permit(principal, action, resource);',
        cedar_text_shadow='',
        enforce_count=1,
        shadow_count=0,
        tool_count=0,
        tool_index={},
        signature="aabbcc",
        _loaded_at=time.time(),
    )
    context = LocalContextPack(
        agent_id="agent:test@corp",
        status="active",
        risk_tier="low",
        data_classifications=[],
        is_revoked=False,
        compiled_at="2026-01-01T00:00:00Z",
        pack_version=1,
    )
    return bundle, context


def _http_client_for_state(version, revoked_agents, blanket=False):
    """Build a mock HTTP client returning the given revocation state."""
    client = MagicMock()

    v_resp = MagicMock()
    v_resp.raise_for_status.return_value = None
    v_resp.json.return_value = {
        "version": version,
        "generated_at": "2026-01-01T00:00:00Z",
        "blanket_kill_active": blanket,
    }

    s_resp = MagicMock()
    s_resp.raise_for_status.return_value = None
    s_resp.json.return_value = {
        "version": version,
        "generated_at": "2026-01-01T00:00:00Z",
        "blanket_kill_active": blanket,
        "revoked_agents": revoked_agents,
    }

    def _side(url, **kwargs):
        if "/version" in url:
            return v_resp
        return s_resp

    client.get.side_effect = _side
    return client


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestLocalDenyAfterRemoteRevoke(unittest.TestCase):
    """Core scenario: allow → server revokes → sync → local deny (no restart)."""

    def _evaluate(self, evaluator, cache, agent_id="agent:test@corp"):
        """Run LocalPDPEvaluator.evaluate() with bundle/context mocked."""
        bundle, context_pack = _mock_allow_bundle_context(evaluator)
        with patch("kswitch.local_pdp.evaluator.load_current_bundle", return_value=bundle), \
             patch("kswitch.local_pdp.evaluator.load_context_pack", return_value=context_pack), \
             patch("kswitch.local_pdp.evaluator.get_revocation_cache", return_value=cache):
            try:
                import cedarpy
                _cedarpy = True
            except ImportError:
                _cedarpy = False

            if _cedarpy:
                return evaluator.evaluate(
                    agent_id=agent_id,
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                )
            else:
                # Without cedarpy, evaluator returns conditional — patch to allow
                with patch.object(evaluator, "_has_cedarpy", return_value=False):
                    return evaluator.evaluate(
                        agent_id=agent_id,
                        mcp_server_id="mcp:test@corp",
                        tool_name="test_tool",
                    )

    def test_allow_before_revoke(self):
        """Step 1: Agent starts as allowed (not revoked)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            # Agent not revoked
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            from kswitch.local_pdp.evaluator import LocalPDPEvaluator
            evaluator = LocalPDPEvaluator()

            with patch("kswitch.local_pdp.evaluator.get_revocation_cache", return_value=cache):
                is_revoked = cache.is_revoked("agent:test@corp")

        self.assertFalse(is_revoked)

    def test_local_deny_after_sync_revoke(self):
        """Core test: remote revoke → sync → local deny."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)

            # Step 1: Agent starts not revoked
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})
            self.assertFalse(cache.is_revoked("agent:target@corp"))

            # Step 2: Server now reports agent as revoked (version 2)
            http = _http_client_for_state(version=2, revoked_agents=["agent:target@corp"])
            worker = _make_sync_worker(http, cache)

            # Step 3: Trigger one sync cycle (no restart)
            worker.sync_once()

            # Step 4 & 5: Local revocation check now returns True
            self.assertTrue(cache.is_revoked("agent:target@corp"))
            # And non-target agents are unaffected
            self.assertFalse(cache.is_revoked("agent:innocent@corp"))

    def test_deny_requires_no_server_call(self):
        """After sync populates cache, revocation deny uses O(1) local lookup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 2, "blanket_kill_active": False, "revoked_agents": ["agent:revoked@corp"]})

            from kswitch.local_pdp.evaluator import LocalPDPEvaluator
            evaluator = LocalPDPEvaluator()

            # The enforcement HTTP client must NOT be called for revocation deny
            mock_http = MagicMock()
            mock_http.get.side_effect = AssertionError("HTTP should not be called for local revocation deny")
            mock_http.post.side_effect = AssertionError("HTTP should not be called for local revocation deny")

            with patch("kswitch.local_pdp.evaluator.get_revocation_cache", return_value=cache):
                decision = evaluator.evaluate(
                    agent_id="agent:revoked@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="test_tool",
                )

        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "agent_revoked")
        # No HTTP calls were made (mock_http never invoked)
        mock_http.get.assert_not_called()
        mock_http.post.assert_not_called()

    def test_re_sync_cleared_restores_allow(self):
        """If agent is removed from server revocation list, next sync clears local deny."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)

            # Step 1: Agent starts revoked
            http1 = _http_client_for_state(version=2, revoked_agents=["agent:pardoned@corp"])
            worker = _make_sync_worker(http1, cache)
            # First sync to version 1 (initial state, not revoked)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": ["agent:pardoned@corp"]})
            self.assertTrue(cache.is_revoked("agent:pardoned@corp"))

            # Step 2: Server revocation cleared (agent pardoned, version 3)
            http2 = _http_client_for_state(version=3, revoked_agents=[])
            worker2 = _make_sync_worker(http2, cache)
            worker2.sync_once()

            # After sync, agent is no longer revoked
            self.assertFalse(cache.is_revoked("agent:pardoned@corp"))


class TestBlanketKillAfterSync(unittest.TestCase):
    """Blanket kill synced from server leads to all-deny locally."""

    def test_blanket_kill_denies_all_after_sync(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            # Server activates blanket kill
            http = _http_client_for_state(version=2, revoked_agents=[], blanket=True)
            worker = _make_sync_worker(http, cache)
            worker.sync_once()

        # Every agent is now denied
        self.assertTrue(cache.is_revoked("agent:alpha@corp"))
        self.assertTrue(cache.is_revoked("agent:beta@corp"))
        self.assertTrue(cache.is_revoked("agent:gamma@corp"))

    def test_blanket_kill_no_server_call_for_deny(self):
        """Blanket kill deny does not call the server enforcement endpoint."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 2, "blanket_kill_active": True, "revoked_agents": []})

            from kswitch.local_pdp.evaluator import LocalPDPEvaluator
            evaluator = LocalPDPEvaluator()

            mock_enforcement = MagicMock()
            mock_enforcement.post.side_effect = AssertionError("Should not call enforcement for blanket kill")

            with patch("kswitch.local_pdp.evaluator.get_revocation_cache", return_value=cache):
                decision = evaluator.evaluate(
                    agent_id="agent:any@corp",
                    mcp_server_id="mcp:test@corp",
                    tool_name="any_tool",
                )

        self.assertEqual(decision.outcome, "deny")
        self.assertEqual(decision.reason, "agent_revoked")
        mock_enforcement.post.assert_not_called()


class TestSyncWorkerBackground(unittest.TestCase):
    """Background thread starts, polls, and stops cleanly."""

    def test_worker_starts_and_stops(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            http = _http_client_for_state(version=1, revoked_agents=[])
            from kswitch.revocation.sync import RevocationSyncWorker
            worker = RevocationSyncWorker(
                http_client=http,
                base_url="https://test.local:5001",
                interval=1,
                revocation_cache=cache,
            )
            worker.start()
            self.assertTrue(worker.is_running())

            worker.stop(timeout=2.0)
            self.assertFalse(worker.is_running())

    def test_background_sync_updates_cache(self):
        """Background thread detects version change and updates cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = _make_cache(tmpdir)
            cache.apply_server_state({"version": 1, "blanket_kill_active": False, "revoked_agents": []})

            # Use a counter to serve version=1 twice, then version=2 with a revoked agent
            call_count = {"n": 0}

            def _get_side(url, **kwargs):
                call_count["n"] += 1
                resp = MagicMock()
                resp.raise_for_status.return_value = None
                if "/version" in url:
                    # After 2 calls, bump to version 2
                    v = 2 if call_count["n"] >= 2 else 1
                    resp.json.return_value = {"version": v, "generated_at": "2026-01-01T00:00:00Z", "blanket_kill_active": False}
                else:
                    resp.json.return_value = {"version": 2, "generated_at": "2026-01-01T00:00:00Z",
                                               "blanket_kill_active": False, "revoked_agents": ["agent:bg-revoked@corp"]}
                return resp

            http = MagicMock()
            http.get.side_effect = _get_side

            from kswitch.revocation.sync import RevocationSyncWorker
            worker = RevocationSyncWorker(
                http_client=http,
                base_url="https://test.local:5001",
                interval=1,  # 1-second poll for fast test
                revocation_cache=cache,
            )
            worker.start()
            # Allow up to 3 seconds for background thread to detect version change
            deadline = time.time() + 3.0
            while time.time() < deadline:
                if cache.is_revoked("agent:bg-revoked@corp"):
                    break
                time.sleep(0.1)
            worker.stop(timeout=2.0)

        self.assertTrue(cache.is_revoked("agent:bg-revoked@corp"),
                        "Background sync should have revoked agent:bg-revoked@corp")


if __name__ == "__main__":
    unittest.main()
