#!/usr/bin/env python3
"""Example: Governed MCP tool invocation via KSwitchRuntime.

This is the SUPPORTED production pattern for gating MCP tool calls through
KSwitch governance policies. It uses the governed invocation path:

    KSwitchRuntime.invoke() → enforce → tool execution → output filtering → audit

The old pattern (client.enforcement.enforce_mcp_call()) is deprecated and does
NOT provide bypass prevention, output filtering, or obligation blocking.
Use KSwitchRuntime.invoke() or KSwitchInterceptor.check_and_invoke() instead.

Usage:
    python mcp_enforcement.py
"""

from kswitch import (
    KSwitchClient,
    KSwitchRuntime,
    KSwitchEnforcementError,
    KSwitchObligationError,
    OutputDeniedError,
)


# ── Simulated MCP tool implementations ───────────────────────────────────────

def read_records(table: str, limit: int = 10) -> dict:
    """Simulated MCP tool: read database records."""
    return {"records": [{"id": i, "table": table} for i in range(limit)]}


def delete_records(table: str, ids: list) -> dict:
    """Simulated MCP tool: delete database records."""
    return {"deleted": len(ids), "table": table}


# ── Governed invocation (supported path) ─────────────────────────────────────

def main():
    client = KSwitchClient(
        base_url="https://localhost:5001",
        client_id="mcp-database-server",
        client_secret="mcp-secret",
        keycloak_url="http://keycloak:8080",
        verify_ssl=False,
    )

    # Create the governed runtime for this agent + MCP server.
    # The runtime is the primary public invocation surface.
    runtime = KSwitchRuntime(
        agent_id="agent:fraud-detector@bank.internal",
        mcp_server_id="mcp:database@bank.internal",
        client=client,  # enables server fallback + revocation sync + audit
    )

    # Register tools. runtime.register() returns a GovernedTool — the
    # governed callable that always routes through enforcement.
    runtime.register("read_records", read_records)
    runtime.register("delete_records", delete_records)

    print("Checking tool call authorizations via governed runtime\n")

    # ── Governed invocation ───────────────────────────────────────────────────
    # This is the ONLY supported production path.
    # enforce → output filter → audit is automatic — no manual wiring needed.

    calls = [
        ("read_records", {"table": "customers", "limit": 10}),
        ("delete_records", {"table": "customers", "ids": [1, 2, 3]}),
    ]

    for tool_name, kwargs in calls:
        print(f"Invoking {tool_name}...")
        try:
            result = runtime.invoke(tool_name, **kwargs)
            print(f"  ALLOWED — result: {result}")
        except KSwitchEnforcementError as e:
            print(f"  DENIED — reason: {e.args[0]}")
        except KSwitchObligationError as e:
            print(f"  BLOCKED (obligation) — reason: {e.reason}")
        except OutputDeniedError:
            print(f"  OUTPUT DENIED — policy prevents export of this result")
        print()

    # Print observability diagnostics
    print("Revocation sync:", runtime.revocation_sync_diagnostics()["sync_worker"]["running"])
    print("Audit forwarding:", runtime.audit_diagnostics()["forwarding_enabled"])

    runtime.stop_revocation_sync()
    runtime.stop_audit_sender()
    client.close()


if __name__ == "__main__":
    main()
