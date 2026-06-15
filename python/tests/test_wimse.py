"""Tests for WIMSE delegation assertion builder and SPIRE integration.

Covers:
  - WIMSEAssertion field validation (purpose, resource_context, workflow_id, depth, TTL)
  - WIMSEAssertion.sign() ES256 JWT production and key-type rejection
  - WIMSEChainBuilder hop management (depth tracking, parent_jti propagation)
  - WIMSEChainBuilder.to_header_value() format and size enforcement
  - _debug_decode_chain safety
  - SVIDBundle dataclass
  - SPIREUnavailableError on missing socket
"""

from __future__ import annotations

import base64
import json
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from kswitch.spire import SPIREUnavailableError, SVIDBundle
from kswitch.wimse import (
    MAX_ASSERTION_TTL_SECONDS,
    MAX_CHAIN_DEPTH,
    MAX_CHAIN_HEADER_BYTES,
    MAX_PURPOSE_LEN,
    MAX_RESOURCE_CONTEXT_LEN,
    MAX_WORKFLOW_ID_LEN,
    WIMSEAssertion,
    WIMSEChainBuilder,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def ec_private_key():
    """Generate an EC P-256 private key for testing."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture()
def ec_private_key_pem(ec_private_key):
    """PEM-encoded EC P-256 private key bytes."""
    return ec_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


@pytest.fixture()
def rsa_private_key_pem():
    """PEM-encoded RSA private key bytes (wrong key type for ES256)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


@pytest.fixture()
def base_assertion():
    """A valid WIMSEAssertion with minimal required fields."""
    return WIMSEAssertion(
        iss="spiffe://bank.internal/agent/payments",
        sub="spiffe://bank.internal/agent/risk-engine",
        scope="payments:read",
        purpose="fraud-check",
        resource_context="account:123456",
        root_session_id="sess-abc-123",
    )


def _mock_svid_bundle(ec_private_key_pem):
    """Create a mock SVIDBundle for testing."""
    return SVIDBundle(
        private_key_pem=ec_private_key_pem,
        spiffe_id="spiffe://bank.internal/agent/payments",
    )


# ── WIMSEAssertion.validate() ────────────────────────────────────────────────


class TestWIMSEAssertionValidation:
    def test_purpose_exceeds_max_length(self, base_assertion):
        base_assertion.purpose = "x" * (MAX_PURPOSE_LEN + 1)
        with pytest.raises(ValueError, match="purpose exceeds"):
            base_assertion.validate()

    def test_purpose_at_max_length_ok(self, base_assertion):
        base_assertion.purpose = "x" * MAX_PURPOSE_LEN
        base_assertion.validate()  # should not raise

    def test_resource_context_exceeds_max_length(self, base_assertion):
        base_assertion.resource_context = "x" * (MAX_RESOURCE_CONTEXT_LEN + 1)
        with pytest.raises(ValueError, match="resource_context exceeds"):
            base_assertion.validate()

    def test_resource_context_at_max_length_ok(self, base_assertion):
        base_assertion.resource_context = "x" * MAX_RESOURCE_CONTEXT_LEN
        base_assertion.validate()  # should not raise

    def test_workflow_id_exceeds_max_length(self, base_assertion):
        base_assertion.workflow_id = "w" * (MAX_WORKFLOW_ID_LEN + 1)
        with pytest.raises(ValueError, match="workflow_id exceeds"):
            base_assertion.validate()

    def test_workflow_id_none_ok(self, base_assertion):
        base_assertion.workflow_id = None
        base_assertion.validate()  # should not raise

    def test_delegation_depth_exceeds_max(self, base_assertion):
        base_assertion.delegation_depth = MAX_CHAIN_DEPTH + 1
        with pytest.raises(ValueError, match="delegation_depth"):
            base_assertion.validate()

    def test_delegation_depth_at_max_ok(self, base_assertion):
        base_assertion.delegation_depth = MAX_CHAIN_DEPTH
        base_assertion.validate()  # should not raise

    def test_ttl_exceeds_max(self, base_assertion):
        base_assertion.ttl_seconds = MAX_ASSERTION_TTL_SECONDS + 1
        with pytest.raises(ValueError, match="ttl_seconds exceeds"):
            base_assertion.validate()

    def test_ttl_at_max_ok(self, base_assertion):
        base_assertion.ttl_seconds = MAX_ASSERTION_TTL_SECONDS
        base_assertion.validate()  # should not raise


# ── WIMSEAssertion.sign() ────────────────────────────────────────────────────


class TestWIMSEAssertionSign:
    def test_sign_produces_three_part_jwt(self, base_assertion, ec_private_key_pem):
        token = base_assertion.sign(ec_private_key_pem)
        parts = token.split(".")
        assert len(parts) == 3, "JWT must have header.payload.signature"

    def test_sign_header_contains_es256(self, base_assertion, ec_private_key_pem):
        token = base_assertion.sign(ec_private_key_pem)
        header_b64 = token.split(".")[0]
        # Add padding
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        assert header["alg"] == "ES256"
        assert header["typ"] == "wimse+jwt"

    def test_sign_payload_contains_required_claims(self, base_assertion, ec_private_key_pem):
        token = base_assertion.sign(ec_private_key_pem)
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        assert payload["iss"] == base_assertion.iss
        assert payload["sub"] == base_assertion.sub
        assert payload["scope"] == "payments:read"
        assert payload["purpose"] == "fraud-check"
        assert payload["resource_context"] == "account:123456"
        assert payload["root_session_id"] == "sess-abc-123"
        assert payload["delegation_depth"] == 1
        assert "iat" in payload
        assert "exp" in payload
        assert "jti" in payload
        # parent_jti is None at hop 1 -- should still be present as null
        assert payload["parent_jti"] is None

    def test_sign_rejects_rsa_key(self, base_assertion, rsa_private_key_pem):
        with pytest.raises(TypeError, match="EC.*P-256"):
            base_assertion.sign(rsa_private_key_pem)

    def test_sign_validates_fields_first(self, base_assertion, ec_private_key_pem):
        base_assertion.purpose = "x" * (MAX_PURPOSE_LEN + 1)
        with pytest.raises(ValueError, match="purpose exceeds"):
            base_assertion.sign(ec_private_key_pem)


# ── WIMSEChainBuilder ────────────────────────────────────────────────────────


class TestWIMSEChainBuilder:
    def _patch_fetch_svid(self, ec_private_key_pem):
        """Return a context manager that patches fetch_svid in the spire module."""
        bundle = _mock_svid_bundle(ec_private_key_pem)
        return patch("kswitch.spire.fetch_svid", return_value=bundle)

    def test_add_hop_increments_depth(self, ec_private_key_pem):
        builder = WIMSEChainBuilder()
        with self._patch_fetch_svid(ec_private_key_pem):
            builder.add_hop(
                delegatee_spiffe_id="spiffe://bank.internal/agent/risk",
                scope="payments:read",
                purpose="fraud-check",
                resource_context="account:123",
                root_session_id="sess-001",
            )
        assert builder.depth == 1

        with self._patch_fetch_svid(ec_private_key_pem):
            builder.add_hop(
                delegatee_spiffe_id="spiffe://bank.internal/agent/ml",
                scope="payments:read",
                purpose="scoring",
                resource_context="account:123",
                root_session_id="sess-001",
            )
        assert builder.depth == 2

    def test_add_hop_enforces_max_depth(self, ec_private_key_pem):
        builder = WIMSEChainBuilder()
        for i in range(MAX_CHAIN_DEPTH):
            with self._patch_fetch_svid(ec_private_key_pem):
                builder.add_hop(
                    delegatee_spiffe_id=f"spiffe://bank.internal/agent/hop{i}",
                    scope="payments:read",
                    purpose="test",
                    resource_context="ctx",
                    root_session_id="sess-001",
                )
        assert builder.depth == MAX_CHAIN_DEPTH

        # The 4th hop should raise
        with self._patch_fetch_svid(ec_private_key_pem):
            with pytest.raises(ValueError, match="Chain depth.*exceeds maximum"):
                builder.add_hop(
                    delegatee_spiffe_id="spiffe://bank.internal/agent/overflow",
                    scope="payments:read",
                    purpose="test",
                    resource_context="ctx",
                    root_session_id="sess-001",
                )

    def test_to_header_value_space_separated(self, ec_private_key_pem):
        builder = WIMSEChainBuilder()
        for i in range(2):
            with self._patch_fetch_svid(ec_private_key_pem):
                builder.add_hop(
                    delegatee_spiffe_id=f"spiffe://bank.internal/agent/hop{i}",
                    scope="payments:read",
                    purpose="test",
                    resource_context="ctx",
                    root_session_id="sess-001",
                )
        value = builder.to_header_value()
        tokens = value.split(" ")
        assert len(tokens) == 2
        # Each token should be a valid JWT (3 dot-separated parts)
        for t in tokens:
            assert len(t.split(".")) == 3

    def test_to_header_value_enforces_size_limit(self, ec_private_key_pem):
        builder = WIMSEChainBuilder()
        # Manually inject oversized chain to trigger the limit
        builder._chain = ["x" * (MAX_CHAIN_HEADER_BYTES + 1)]
        with pytest.raises(ValueError, match="header limit"):
            builder.to_header_value()

    def test_parent_jti_none_at_hop_1_set_at_hop_2(self, ec_private_key_pem):
        builder = WIMSEChainBuilder()
        with self._patch_fetch_svid(ec_private_key_pem):
            builder.add_hop(
                delegatee_spiffe_id="spiffe://bank.internal/agent/hop0",
                scope="payments:read",
                purpose="test",
                resource_context="ctx",
                root_session_id="sess-001",
            )
        # Decode first hop
        hop1_payload = WIMSEChainBuilder._debug_decode_chain(builder.to_header_value())[0]
        assert hop1_payload["parent_jti"] is None
        hop1_jti = hop1_payload["jti"]

        with self._patch_fetch_svid(ec_private_key_pem):
            builder.add_hop(
                delegatee_spiffe_id="spiffe://bank.internal/agent/hop1",
                scope="payments:read",
                purpose="test",
                resource_context="ctx",
                root_session_id="sess-001",
            )
        # Decode second hop
        hop2_payload = WIMSEChainBuilder._debug_decode_chain(builder.to_header_value())[1]
        assert hop2_payload["parent_jti"] == hop1_jti

    def test_debug_decode_chain_roundtrip(self, ec_private_key_pem):
        builder = WIMSEChainBuilder()
        with self._patch_fetch_svid(ec_private_key_pem):
            builder.add_hop(
                delegatee_spiffe_id="spiffe://bank.internal/agent/target",
                scope="payments:read",
                purpose="test-purpose",
                resource_context="test-ctx",
                root_session_id="sess-001",
            )
        header_value = builder.to_header_value()
        decoded = WIMSEChainBuilder._debug_decode_chain(header_value)
        assert len(decoded) == 1
        assert decoded[0]["purpose"] == "test-purpose"
        assert decoded[0]["resource_context"] == "test-ctx"
        assert decoded[0]["scope"] == "payments:read"

    def test_debug_decode_chain_handles_invalid_jwt(self):
        decoded = WIMSEChainBuilder._debug_decode_chain("not-a-jwt")
        assert len(decoded) == 1
        assert "_error" in decoded[0]


# ── SVIDBundle ────────────────────────────────────────────────────────────────


class TestSVIDBundle:
    def test_svid_bundle_holds_key_and_id(self, ec_private_key_pem):
        bundle = SVIDBundle(
            private_key_pem=ec_private_key_pem,
            spiffe_id="spiffe://bank.internal/agent/test",
        )
        assert bundle.private_key_pem == ec_private_key_pem
        assert bundle.spiffe_id == "spiffe://bank.internal/agent/test"

    def test_svid_bundle_fields_accessible(self):
        bundle = SVIDBundle(
            private_key_pem=b"fake-pem",
            spiffe_id="spiffe://example.org/workload",
        )
        assert isinstance(bundle.private_key_pem, bytes)
        assert isinstance(bundle.spiffe_id, str)


# ── SPIREUnavailableError ─────────────────────────────────────────────────────


class TestSPIREUnavailableError:
    def test_raised_when_socket_missing(self):
        with patch("kswitch.spire.os.path.exists", return_value=False):
            from kswitch.spire import fetch_svid

            with pytest.raises(SPIREUnavailableError, match="socket not found"):
                fetch_svid()

    def test_error_is_exception_subclass(self):
        err = SPIREUnavailableError("test message")
        assert isinstance(err, Exception)
        assert str(err) == "test message"


# ── Additional edge cases ─────────────────────────────────────────────────────


class TestEdgeCases:
    def test_assertion_jti_auto_generated(self):
        a1 = WIMSEAssertion(
            iss="spiffe://a", sub="spiffe://b", scope="s",
            purpose="p", resource_context="r", root_session_id="sess",
        )
        a2 = WIMSEAssertion(
            iss="spiffe://a", sub="spiffe://b", scope="s",
            purpose="p", resource_context="r", root_session_id="sess",
        )
        assert a1.jti != a2.jti, "Each assertion should get a unique jti"

    def test_sign_exp_is_iat_plus_ttl(self, ec_private_key_pem):
        assertion = WIMSEAssertion(
            iss="spiffe://a", sub="spiffe://b", scope="s",
            purpose="p", resource_context="r", root_session_id="sess",
            ttl_seconds=60,
        )
        token = assertion.sign(ec_private_key_pem)
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        assert payload["exp"] - payload["iat"] == 60
