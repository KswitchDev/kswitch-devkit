"""Static contract tests for B005.2 managed/developer MCP profiles."""

from __future__ import annotations

import json
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "configs" / "b005"
TOOL_SURFACE = ["fetch", "search", "policy_check", "get_policy", "health"]
GENERIC_IDPS = {
    "microsoft_entra",
    "ping_identity",
    "okta",
    "forgerock",
    "slashid",
    "active_directory_federation",
    "generic_oidc",
}


def _profile(name: str) -> dict:
    return json.loads((CONFIG_DIR / name).read_text())


def test_managed_profile_registers_only_kswitch_service_mcp() -> None:
    config = _profile("managed-claude-code.json")

    assert list(config["mcpServers"]) == ["kswitch_service"]
    server = config["mcpServers"]["kswitch_service"]
    assert server["command"] == "kswitch-service-mcp"
    assert config["kswitchProfile"]["service"] == "kswitch_service"
    assert config["kswitchProfile"]["toolSurface"] == TOOL_SURFACE


def test_managed_profile_denies_native_fetch_search_and_unmanaged_mcp() -> None:
    config = _profile("managed-claude-code.json")
    profile = config["kswitchProfile"]
    env = config["mcpServers"]["kswitch_service"]["env"]

    assert profile["mode"] == "managed"
    assert profile["advisory"] is False
    assert profile["nativeToolPolicy"] == {
        "fetch": "deny",
        "search": "deny",
        "unmanagedMcpRegistration": "deny",
    }
    assert env["KSWITCH_NATIVE_FETCH"] == "deny"
    assert env["KSWITCH_NATIVE_SEARCH"] == "deny"
    assert env["KSWITCH_UNMANAGED_MCP_REGISTRATION"] == "deny"


def test_managed_profile_is_provider_agnostic_not_keycloak_locked() -> None:
    config = _profile("managed-claude-code.json")
    rendered = json.dumps(config, sort_keys=True).lower()
    idps = set(config["kswitchProfile"]["identity"]["acceptedHumanIdps"])

    assert GENERIC_IDPS.issubset(idps)
    assert "keycloak" not in rendered
    assert "kswitch_keycloak" not in rendered
    assert "OIDC_ISSUER" in config["kswitchProfile"]["identity"]["requiredEnv"]
    assert "OIDC_AUDIENCE" in config["kswitchProfile"]["identity"]["requiredEnv"]


def test_managed_profile_requires_spiffe_workload_identity() -> None:
    config = _profile("managed-claude-code.json")
    identity = config["kswitchProfile"]["identity"]
    env = config["mcpServers"]["kswitch_service"]["env"]

    assert identity["workloadIdentity"] == "spiffe_jwt_svid"
    assert identity["delegationChain"] == "wimse_required_for_multihop"
    assert env["SPIFFE_JWT_ENABLED"] == "true"
    assert "SPIFFE_JWKS_URI" in identity["requiredEnv"]
    assert "SPIFFE_ALLOWED_TRUST_DOMAINS" in identity["requiredEnv"]


def test_developer_profile_is_explicitly_advisory_and_bypassable() -> None:
    config = _profile("developer-claude-code.json")
    profile = config["kswitchProfile"]
    env = config["mcpServers"]["kswitch_service"]["env"]

    assert list(config["mcpServers"]) == ["kswitch_service"]
    assert config["mcpServers"]["kswitch_service"]["command"] == "kswitch-service-mcp"
    assert profile["mode"] == "developer"
    assert profile["advisory"] is True
    assert profile["nativeToolPolicy"] == {
        "fetch": "advisory",
        "search": "advisory",
        "unmanagedMcpRegistration": "advisory",
    }
    assert env["KSWITCH_NATIVE_FETCH"] == "advisory"
    assert any("bypassable" in note for note in profile["notes"])


def test_profile_readme_calls_out_contract_vs_firewall_boundary() -> None:
    readme = (CONFIG_DIR / "README.md").read_text().lower()

    assert "kswitch-service-mcp" in readme
    assert "commercial managed runtime controls" in readme
    assert "not managed-mode enforcement evidence" in readme
