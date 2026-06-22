"""L2a floor rules — hardcoded, immutable, fire from pip install.

LU-001/002/003 only. Higher-numbered LU rules are in the signed policy bundle (L2b).
EP-072, §5.1 L2a layer.
Do not add rules here — add to bundle schema instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Compiled patterns — built once at module load time.
# ---------------------------------------------------------------------------

# LU-002: shell injection characters in tool names.
_LU002_PATTERN: re.Pattern = re.compile(
    r"[;&|`]|\$\(|\.\./|%2e%2e|%00",
    re.IGNORECASE,
)

# LU-003: path traversal / URL injection characters in MCP server IDs.
_LU003_PATTERN: re.Pattern = re.compile(
    r"\.\./|/\.\.|[?#\x00]|%2e%2e|%00|%23|%3f",
    re.IGNORECASE,
)

# LU-001: maximum allowed tool-name length (characters, not bytes).
_LU001_MAX_TOOL_NAME_LEN: int = 128


# ---------------------------------------------------------------------------
# Decision dataclass
# ---------------------------------------------------------------------------

@dataclass
class LocalAccessDecision:
    """Outcome of the L2a floor-rule check."""

    allowed: bool
    reason: str
    rule_id: str | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check(mcp_server_id: str, tool_name: str) -> LocalAccessDecision:
    """Apply LU-001, LU-002, and LU-003 floor rules in order.

    Rules are applied sequentially; the first failing rule short-circuits and
    returns a deny decision.  If all rules pass, a permit decision is returned.

    Parameters
    ----------
    mcp_server_id:
        The MCP server identifier presented by the proxy (e.g.
        ``"acme-corp/payments-mcp"``).
    tool_name:
        The tool name requested by the agent (e.g. ``"list_transactions"``).

    Returns
    -------
    LocalAccessDecision
        ``allowed=True`` with ``reason="l2a_pass"`` on success, or
        ``allowed=False`` with the relevant rule ID and reason on failure.
    """
    # LU-001: tool name length guard.
    if len(tool_name) > _LU001_MAX_TOOL_NAME_LEN:
        return LocalAccessDecision(
            allowed=False,
            reason="Tool name exceeds maximum length of 128 characters (LU-001)",
            rule_id="LU-001",
        )

    # LU-002: shell injection characters in tool name.
    if _LU002_PATTERN.search(tool_name):
        return LocalAccessDecision(
            allowed=False,
            reason="Tool name contains shell-injection characters (LU-002)",
            rule_id="LU-002",
        )

    # LU-003: path traversal / URL injection in MCP server ID.
    if _LU003_PATTERN.search(mcp_server_id):
        return LocalAccessDecision(
            allowed=False,
            reason="MCP server ID contains path traversal or URL injection characters (LU-003)",
            rule_id="LU-003",
        )

    return LocalAccessDecision(allowed=True, reason="l2a_pass")
