"""Tests for BL-047 T9 — proxy-side tool-descriptor hash + drift check.

MCP SDK version: mcp~=1.27.0 (declared in mcp-server/pyproject.toml).
httpx version: httpx~=0.28.1 (declared in mcp-server/pyproject.toml).

Mock assumptions and their grounding (per Engineering Principle §2):
  - ``httpx.AsyncClient.post`` accepts a ``timeout=`` keyword override per
    https://www.python-httpx.org/api/#asyncclient (retrieval 2026-05-20).
    The mocks therefore accept ``**kwargs`` on the recorded ``.post`` call
    so they do not break when ``check_tool_descriptors`` passes the
    5-second timeout override.
  - ``httpx.TimeoutException`` is the documented timeout exception class
    (https://www.python-httpx.org/exceptions/ — retrieval 2026-05-20).
  - ``httpx.ConnectError`` is the documented connection-error class
    (https://www.python-httpx.org/exceptions/ — retrieval 2026-05-20).
  - The T10 control-plane response shape
    ``{"checks": [{"tool_name", "version", "action", "has_drift",
    "current_hash", "baseline_hash", "baseline_status"}, ...]}`` matches
    the live endpoint at
    ``app/routes/mcp_tool_descriptors.py:231-241`` (committed 2026-05-20
    in d9ec6837, read live during this implementation pass).
  - ``kswitch_mcp.mcp_descriptor_canonical.compute_descriptor_hash`` is the
    single source of truth for canonical hashing on BOTH proxy and
    control plane; tests assert determinism end-to-end rather than
    pinning a hard-coded hex digest (the digest is implementation
    detail; the determinism guarantee is the contract).

pytest-asyncio is not declared in mcp-server/pyproject.toml; async tests
are wrapped with ``asyncio.run`` for consistency with existing
``mcp-server/tests/test_proxy.py``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock

# Ensure the mcp-server package is importable when running from the repo root.
_MCP_SERVER_DIR = os.path.join(os.path.dirname(__file__), "..")
if _MCP_SERVER_DIR not in sys.path:
    sys.path.insert(0, _MCP_SERVER_DIR)

import httpx  # noqa: E402

from kswitch_mcp.mcp_descriptor_canonical import compute_descriptor_hash  # noqa: E402
from kswitch_mcp.enforcement_client import KSwitchEnforcementClient  # noqa: E402
from kswitch_mcp.proxy import _build_tool_spec, _drift_check_upstream  # noqa: E402


# ── Helpers ───────────────────────────────────────────────────────────────


def _mock_response(status_code: int, json_body: dict) -> MagicMock:
    """Build a minimal mock of httpx.Response (status_code + .json())."""
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_body
    return r


def _make_enf_client() -> KSwitchEnforcementClient:
    """Return an EnforcementClient with a MagicMock httpx client."""
    client = KSwitchEnforcementClient(
        base_url="https://kswitch.example.com",
        token="test-token",
        verify_ssl=False,
    )
    client._client = MagicMock()
    return client


def _fake_tool(
    name: str = "query_db",
    description: str = "Run a SQL query.",
    input_schema: dict | None = None,
    *,
    annotations: object = None,
    version: object = None,
    include_annotations: bool = True,
    include_version: bool = True,
) -> object:
    """Build a duck-typed MCP Tool object using a tiny class.

    Using a class (not MagicMock) so missing attributes raise AttributeError
    rather than autospec'ing a Mock — that lets us exercise the defensive
    ``getattr(tool, "annotations", None)`` path correctly.
    """

    class _Tool:
        pass

    t = _Tool()
    t.name = name
    t.description = description
    t.inputSchema = input_schema if input_schema is not None else {"type": "object"}
    if include_annotations:
        t.annotations = annotations
    if include_version:
        t.version = version
    return t


# ── _build_tool_spec ──────────────────────────────────────────────────────


class TestBuildToolSpec(unittest.TestCase):
    """_build_tool_spec — defensive parsing + hash determinism."""

    def test_client_hash_matches_compute_descriptor_hash(self):
        """The client_hash MUST equal compute_descriptor_hash over the same fields.

        Determinism is the load-bearing property: proxy-side and
        control-plane-side computations must agree byte-for-byte over
        the canonical form.
        """
        tool = _fake_tool(
            name="query_db",
            description="Run SQL.",
            input_schema={"type": "object", "properties": {"sql": {"type": "string"}}},
            annotations=None,
            version="1.0.0",
        )

        spec = _build_tool_spec(tool)

        # client_hash is added LAST and must not be part of the input.
        self.assertIn("client_hash", spec)
        client_hash = spec["client_hash"]

        # Recompute over a fresh dict that mirrors the canonical fields
        # — the same shape the control plane recomputes after popping
        # client_hash.
        recomputed_input = {k: v for k, v in spec.items() if k != "client_hash"}
        self.assertEqual(client_hash, compute_descriptor_hash(recomputed_input))

    def test_missing_annotations_field_handled(self):
        """A tool object without an ``annotations`` attribute must not raise."""
        tool = _fake_tool(include_annotations=False)
        spec = _build_tool_spec(tool)
        self.assertIsNone(spec["annotations"])
        # And the hash is still computable.
        self.assertEqual(len(spec["client_hash"]), 64)

    def test_missing_version_field_handled(self):
        """A tool object without a ``version`` attribute must not raise.

        Post-BL-047 hash-parity fix (2026-05-20): the canonical builder
        coerces ``version=None`` to ``""`` so the value flows safely
        through the ``mcp_tool_descriptors.version`` ``TEXT NOT NULL``
        column AND matches the E2 absent-version PK convention used by
        ``record_baseline`` / ``check_drift``. See
        ``kswitch_mcp.mcp_descriptor_canonical.build_canonical_tool_spec``.
        """
        tool = _fake_tool(include_version=False)
        spec = _build_tool_spec(tool)
        self.assertEqual(spec["version"], "")
        self.assertEqual(len(spec["client_hash"]), 64)

    def test_unicode_tool_name_round_trips(self):
        """R2 — unicode in name/description must canonicalise deterministically.

        Per ``app/mcp_descriptor_canonical.py:36`` we use
        ``ensure_ascii=False``, so multi-byte UTF-8 must survive the
        canonical form without escape-vs-literal disagreement.
        """
        tool = _fake_tool(
            name="recherche_données",  # French + accents
            description="Recherche les données — 検索する",  # mixed scripts
        )
        spec = _build_tool_spec(tool)
        # Hash is stable across two invocations of the same fields.
        spec2 = _build_tool_spec(tool)
        self.assertEqual(spec["client_hash"], spec2["client_hash"])
        # And it matches a direct recomputation over the canonical fields.
        recomputed_input = {k: v for k, v in spec.items() if k != "client_hash"}
        self.assertEqual(spec["client_hash"], compute_descriptor_hash(recomputed_input))

    def test_annotations_with_model_dump_method_serialised(self):
        """If an upstream returns a Pydantic-style annotations object, we
        normalise it via .model_dump() before hashing — otherwise the
        hash would be over the object's repr() which is not stable."""

        class FakePydanticAnnotations:
            def model_dump(self) -> dict:
                return {"readOnlyHint": True, "destructiveHint": False}

        tool = _fake_tool(annotations=FakePydanticAnnotations())
        spec = _build_tool_spec(tool)
        self.assertEqual(
            spec["annotations"],
            {"readOnlyHint": True, "destructiveHint": False},
        )


# ── _drift_check_upstream — endpoint contract ─────────────────────────────


class TestDriftCheckUpstreamEndpoint(unittest.TestCase):
    """_drift_check_upstream calls /tool-descriptors/check with correct payload."""

    def test_list_tools_calls_descriptor_check_endpoint(self):
        """Verify the POST URL and payload shape match the T10 contract."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            return_value=_mock_response(
                200,
                {
                    "checks": [
                        {
                            "tool_name": "query_db",
                            "version": "",
                            "action": "allow",
                            "has_drift": False,
                            "current_hash": "abc",
                            "baseline_hash": "abc",
                            "baseline_status": "approved",
                        }
                    ]
                },
            )
        )

        tools = [_fake_tool(name="query_db")]
        actions = asyncio.run(_drift_check_upstream(client, "postgres-mcp", tools))

        self.assertEqual(actions, {"query_db": "allow"})

        # Endpoint URL
        called_url = client._client.post.call_args[0][0]
        self.assertEqual(
            called_url, "/api/v1/mcp/postgres-mcp/tool-descriptors/check"
        )

        # Payload shape: {"tools": [{"name", "description", "inputSchema",
        # "annotations", "version", "client_hash"}]}
        payload = client._client.post.call_args.kwargs["json"]
        self.assertIn("tools", payload)
        self.assertEqual(len(payload["tools"]), 1)
        sent_spec = payload["tools"][0]
        self.assertEqual(sent_spec["name"], "query_db")
        self.assertIn("description", sent_spec)
        self.assertIn("inputSchema", sent_spec)
        self.assertIn("annotations", sent_spec)
        self.assertIn("version", sent_spec)
        self.assertIn("client_hash", sent_spec)
        self.assertEqual(len(sent_spec["client_hash"]), 64)  # hex sha256

    def test_check_endpoint_uses_5_second_timeout(self):
        """Per BL-047 T9: 5-second timeout, not the default 10s, on the
        startup critical path."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            return_value=_mock_response(200, {"checks": []})
        )

        asyncio.run(_drift_check_upstream(client, "postgres-mcp", []))
        # Empty tool list short-circuits — won't call post.  Add one tool.
        tools = [_fake_tool(name="t")]
        client._client.post.return_value = _mock_response(
            200,
            {
                "checks": [
                    {
                        "tool_name": "t",
                        "version": "",
                        "action": "allow",
                        "has_drift": False,
                        "current_hash": "x",
                        "baseline_hash": "x",
                        "baseline_status": "approved",
                    }
                ]
            },
        )
        asyncio.run(_drift_check_upstream(client, "postgres-mcp", tools))
        timeout = client._client.post.call_args.kwargs.get("timeout")
        # Either an httpx.Timeout or a float — check we set it to 5s.
        if isinstance(timeout, httpx.Timeout):
            self.assertEqual(timeout.connect, 5.0)
        else:
            self.assertEqual(timeout, 5.0)


# ── _drift_check_upstream — action handling ──────────────────────────────


class TestDriftCheckActions(unittest.TestCase):
    """Action mapping: allow / alert / block."""

    def _make_response(self, action: str) -> MagicMock:
        return _mock_response(
            200,
            {
                "checks": [
                    {
                        "tool_name": "query_db",
                        "version": "",
                        "action": action,
                        "has_drift": action != "allow",
                        "current_hash": "newhash",
                        "baseline_hash": "oldhash",
                        "baseline_status": "approved",
                    }
                ]
            },
        )

    def test_action_allow_returns_allow(self):
        client = _make_enf_client()
        client._client.post = AsyncMock(return_value=self._make_response("allow"))
        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertEqual(actions, {"query_db": "allow"})

    def test_action_alert_returns_alert(self):
        """action=alert means: register the tool but emit a proxy-side
        warning to mirror the control-plane governance event."""
        client = _make_enf_client()
        client._client.post = AsyncMock(return_value=self._make_response("alert"))
        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertEqual(actions, {"query_db": "alert"})

    def test_action_block_returns_block(self):
        """action=block means: do NOT register the tool."""
        client = _make_enf_client()
        client._client.post = AsyncMock(return_value=self._make_response("block"))
        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertEqual(actions, {"query_db": "block"})


# ── _drift_check_upstream — fail-closed contract ──────────────────────────


class TestDriftCheckFailsClosed(unittest.TestCase):
    """The proxy hook MUST return ``None`` on any control-plane error.

    ``None`` is the lifespan-level signal to register ZERO tools from that
    upstream.  Bank-grade: serving an unverified descriptor surface
    defeats TC-135.
    """

    def test_check_endpoint_timeout_fails_closed_no_tools_registered(self):
        """httpx.TimeoutException → None → caller registers no tools."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            side_effect=httpx.TimeoutException("request timed out")
        )

        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertIsNone(actions)

    def test_check_endpoint_5xx_fails_closed(self):
        """HTTP 500 → None (fail closed, NOT fail open like check_access)."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            return_value=_mock_response(500, {"error": "internal"})
        )

        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertIsNone(actions)

    def test_check_endpoint_503_fails_closed(self):
        """HTTP 503 → None (control plane unavailable, no tools served)."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            return_value=_mock_response(503, {"error": "unavailable"})
        )

        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertIsNone(actions)

    def test_check_endpoint_4xx_fails_closed(self):
        """HTTP 400/404 → None — we can't prove the descriptors are safe."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            return_value=_mock_response(404, {"error": "MCP server not found"})
        )

        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertIsNone(actions)

    def test_check_endpoint_connection_error_fails_closed(self):
        """httpx.ConnectError → None."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertIsNone(actions)

    def test_malformed_response_fails_closed(self):
        """Response missing 'checks' key → None (fail closed)."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            return_value=_mock_response(200, {"oops": "wrong shape"})
        )

        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertIsNone(actions)

    def test_unknown_action_value_fails_closed(self):
        """A check entry with action='kaboom' is malformed — fail closed."""
        client = _make_enf_client()
        client._client.post = AsyncMock(
            return_value=_mock_response(
                200,
                {
                    "checks": [
                        {
                            "tool_name": "query_db",
                            "version": "",
                            "action": "kaboom",
                            "has_drift": False,
                            "current_hash": "x",
                            "baseline_hash": "x",
                            "baseline_status": "approved",
                        }
                    ]
                },
            )
        )
        actions = asyncio.run(
            _drift_check_upstream(
                client, "postgres-mcp", [_fake_tool(name="query_db")]
            )
        )
        self.assertIsNone(actions)


# ── Logging surface ───────────────────────────────────────────────────────


class TestDriftCheckLogging(unittest.TestCase):
    """The proxy MUST emit a warning record on every fail-closed path so
    operators can correlate 'no tools served' with a remote outage."""

    def _capture_warnings(self) -> tuple[list[logging.LogRecord], logging.Handler]:
        captured: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured.append(record)

        handler = _Capture(level=logging.WARNING)
        handler.setLevel(logging.WARNING)
        return captured, handler

    def test_timeout_logs_warning(self):
        from kswitch_mcp import enforcement_client as ec

        captured, handler = self._capture_warnings()
        ec.log.addHandler(handler)
        ec.log.setLevel(logging.WARNING)
        try:
            client = _make_enf_client()
            client._client.post = AsyncMock(
                side_effect=httpx.TimeoutException("timed out")
            )
            asyncio.run(
                _drift_check_upstream(
                    client, "postgres-mcp", [_fake_tool(name="query_db")]
                )
            )
        finally:
            ec.log.removeHandler(handler)

        warning_msgs = [r.getMessage() for r in captured]
        self.assertTrue(
            any("failing CLOSED" in m for m in warning_msgs),
            f"Expected a fail-closed warning, got: {warning_msgs}",
        )


if __name__ == "__main__":
    unittest.main()
