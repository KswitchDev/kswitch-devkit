"""KSwitch.ai MCP Server — Trust enforcement for autonomous systems.

Provides MCP tools for agent governance, compliance, enforcement,
identity management, kill switch, policy, and audit capabilities.

Works with any MCP-compatible tool: Claude Code, Cursor, Windsurf,
OpenCode, OpenClaw, Cline, and more.
"""

__version__ = "1.39.0"

def __getattr__(name: str):
    if name == "mcp":
        from kswitch_mcp.server import mcp

        return mcp
    if name == "KSwitchAPIClient":
        from kswitch_mcp.client import KSwitchAPIClient

        return KSwitchAPIClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
