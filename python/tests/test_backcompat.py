"""
test_backcompat.py — SDK one-version-back contract test scaffolding (Python).

Closes the EP-050 §W4 acceptance-criterion gap:

    "SDK contract tests pass against both current and one-version-back
     server"

    — docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md §W4
      (retrieved 2026-04-22)

This file is **scaffolding**. The original Wave 1 Agent F version targeted
v1.32/v1.34, but that became stale after the product advanced to v1.37.1-pg.
This refresh retargets the placeholders to the current release line:
v1.37.1-pg current and v1.37.0-pg one-version-back. The real payload
assertions will be filled in by Round 2 once v1.37.0 schema fixtures under
`sdks/_schemas/v1.37.0/` are populated from the v1.37.0 OpenAPI spec — see
`sdks/_schemas/v1.37.0/README.md` for the retrieval plan. Until then, each
contract test is marked `xfail(strict=True)`: it documents the CONTRACT,
fails loudly if someone later removes the marker without implementing the
body, and pytest reports it as an expected failure (green) rather than an
error.

Version target note
-------------------
The current product version is ``1.37.1-pg`` (root ``VERSION``). The previous
released tag is ``v1.37.0-pg``. The active "one-version-back" contract is
therefore ``v1.37.0``.

Vendor citations
----------------
- ``pytest.mark.xfail(strict=True, ...)``:
  https://docs.pytest.org/en/stable/how-to/skipping.html#xfail-mark-test-functions-as-expected-to-fail
  (retrieved 2026-04-22). When ``strict=True`` is set, an XPASS (test
  unexpectedly passing) is reported as a FAILURE — which is the behaviour we
  want here, so that a future engineer who removes the marker without
  implementing the body gets a loud signal.
- EP-050 §W4 spec:
  ``docs/execution-packs/KS-EP-050-RUNTIME-RESILIENCE-AND-CONTROL-PLANE-STABILITY.md``
  (retrieved 2026-04-22).

Assumption class (CLAUDE.md engineering principle 3)
----------------------------------------------------
The v1.37.0 and v1.37.1 release pins are **vendor-documented** by git tags
and the root ``VERSION`` file. The concrete wire-contract payloads remain
**inferred / untested** until Round 2 commits real schema exports into
``sdks/_schemas/v1.37.0/`` and ``sdks/_schemas/v1.37.1/``.
"""

from __future__ import annotations

import pathlib

import pytest

# ---------------------------------------------------------------------------
# Contract versions exercised by this test module.
# v1.37.1 = current server (see root VERSION).
# v1.37.0 = one-version-back (previous release tag).
# ---------------------------------------------------------------------------
SCHEMA_VERSIONS = ("v1.37.0", "v1.37.1")

# Shared xfail reason string, cited to the EP that created this contract.
_XFAIL_REASON = (
    "v1.37.0/v1.37.1 schema pins pending — spec acceptance criterion EP-050 §W4. "
    "Scaffolding commit leaves bodies unpopulated until Round 2 exports "
    "the OpenAPI artefacts into sdks/_schemas/v1.37.0/ and "
    "sdks/_schemas/v1.37.1/. See those README files."
)

# Schema fixture directory resolution. Asserted as a sanity check below so the
# contract test file *fails collection* if the fixture scaffolding is deleted.
_SCHEMAS_ROOT = (
    pathlib.Path(__file__).resolve().parent.parent.parent / "_schemas"
)


def test_schema_fixture_directories_exist() -> None:
    """Collection-time guard: both schema version directories must exist.

    This is NOT xfail — it is a real assertion that holds today. If a future
    refactor accidentally deletes the current schema pin directories, the
    contract test module must fail loudly rather than silently reporting all
    xfails as green.
    """
    for version in SCHEMA_VERSIONS:
        version_dir = _SCHEMAS_ROOT / version
        assert version_dir.is_dir(), (
            f"Expected schema fixture directory at {version_dir} "
            f"(see sdks/_schemas/{version}/README.md for the pin reference)."
        )
        readme = version_dir / "README.md"
        assert readme.is_file(), (
            f"Expected pin-reference README at {readme}. "
            f"This file documents the retrieval date, version, and "
            f"assumption class per CLAUDE.md engineering principles §3."
        )


# ---------------------------------------------------------------------------
# Contract placeholders. All xfail(strict=True) — they encode the contract
# without asserting on concrete bytes. Round 2 replaces each body with a
# real round-trip test against the v1.37.0 and v1.37.1 fixtures, and removes
# the xfail marker.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason=_XFAIL_REASON)
def test_register_agent_request_shape_v1_37_0_accepted() -> None:
    """POST /api/v1/agents request envelope produced by the current SDK must
    remain accepted by a v1.37.0 server.

    Contract: the v1.37.1 SDK MUST NOT add new REQUIRED fields to the register
    request. Additive optional fields are allowed; removing or renaming
    required fields is a breaking change.
    """
    # TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
    raise NotImplementedError("v1.37.0 register_agent request fixture pending")


@pytest.mark.xfail(strict=True, reason=_XFAIL_REASON)
def test_evaluate_enforcement_v1_37_0_response_shape() -> None:
    """POST /api/v1/enforcement/evaluate v1.37.0 response envelope must still
    deserialise cleanly through the current SDK.

    Contract: fields present in v1.37.0 (``decision``, ``policy_id``,
    ``matched_rules``, ``deny_reason``, etc.) must still parse through the
    v1.37.1 SDK. Additive fields in v1.37.1 must remain optional for older
    server payloads.
    """
    # TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
    raise NotImplementedError("v1.37.0 evaluate_enforcement response fixture pending")


@pytest.mark.xfail(strict=True, reason=_XFAIL_REASON)
def test_wimse_chain_v1_37_0_envelope_accepted() -> None:
    """WIMSE delegation chain envelope produced at v1.37.0 must verify under
    the current SDK's chain validator (``sdks/python/kswitch/wimse.py``).

    Contract: per-hop ES256 signing, chain depth limit, TTL, and the
    ``WIMSE-Assertion`` header encoding (space-separated JWTs, 8KB cap) are
    all frozen at D5. Any v1.37.1 header-shape change MUST be additive.
    """
    # TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
    raise NotImplementedError("v1.37.0 WIMSE chain envelope fixture pending")


@pytest.mark.xfail(strict=True, reason=_XFAIL_REASON)
def test_kill_switch_ack_v1_37_0_shape_unchanged() -> None:
    """Kill-switch acknowledgement payload shape MUST be byte-for-byte
    compatible between v1.37.0 and v1.37.1.

    Contract: kill-switch is an audit-critical surface under
    ``.claude/rules/compliance.md`` — NO additive or subtractive changes to
    the ack shape are permitted without a new major SDK version. This test
    will assert strict shape equality across both schema fixtures once
    populated.
    """
    # TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
    raise NotImplementedError("v1.37.0 kill_switch_ack fixture pending")


@pytest.mark.xfail(strict=True, reason=_XFAIL_REASON)
def test_deny_reason_v1_37_0_forward_compat_unknown() -> None:
    """Forward-compat: deny reason parsing must keep the UNKNOWN fallback.

    * When an older or partial server response omits ``deny_reason``, the SDK
      decoder must return the SDK-local ``DenyReason.UNKNOWN`` fallback, NOT
      raise.
    * When a future server emits a ``deny_reason`` value unknown to the SDK,
      the decoder must also return ``DenyReason.UNKNOWN`` — the
      forward-compat invariant on the enum parser in
      ``sdks/python/kswitch/deny_reason.py``.

    Round 2 splits this into concrete v1.37.0/v1.37.1 round-trip assertions.
    """
    # TODO(BL-backcompat-round-2): populate from OpenAPI spec at v1.37.0 tag.
    raise NotImplementedError("v1.37.0 deny_reason forward-compat fixture pending")
