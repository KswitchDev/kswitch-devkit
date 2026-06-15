#!/usr/bin/env python3
"""Example: Fleet monitoring — health, compliance, risk assessment.

Usage:
    python fleet_monitoring.py
"""

from kswitch import KSwitchClient


def main():
    with KSwitchClient(base_url="https://localhost:5001", token="your-token", verify_ssl=False) as client:
        # 1. Dashboard overview
        print("=== Governance Dashboard ===")
        dashboard = client.dashboard()
        print(f"  Total agents: {dashboard.get('total_agents', 'N/A')}")
        print(f"  Total MCP servers: {dashboard.get('total_mcp_servers', 'N/A')}")
        print(f"  Agents by status: {dashboard.get('agents_by_status', {})}")

        # 2. Fleet health
        print("\n=== Fleet Health ===")
        health = client.enforcement.get_fleet_health()
        print(f"  Total: {health.total_agents}")
        print(f"  Healthy: {health.healthy}")
        print(f"  Unhealthy: {health.unhealthy}")
        print(f"  Unknown: {health.unknown}")

        # 3. Fleet agents
        print("\n=== Fleet Agents ===")
        agents = client.enforcement.list_fleet_agents()
        for agent in agents[:10]:
            print(f"  {agent.display_name}: {agent.status} (health: {agent.health})")

        # 4. Toxic combo compliance dashboard
        print("\n=== Compliance Dashboard ===")
        compliance = client.compliance.get_dashboard()
        print(f"  Total violations: {compliance.total_violations}")
        print(f"  Clean agents: {compliance.clean_agents}")
        print(f"  By severity: {compliance.violation_counts_by_severity}")

        # 5. Event delivery stats
        print("\n=== Event Delivery ===")
        stats = client.events.get_stats()
        print(f"  Pending: {stats.pending}")
        print(f"  Delivered: {stats.delivered}")
        print(f"  Failed: {stats.failed}")
        print(f"  Dead letter: {stats.dead_letter}")
        print(f"  Delivery rate: {stats.delivery_rate}%")

        # 6. Identity stats
        print("\n=== Identity Stats ===")
        id_stats = client.identity.get_stats()
        print(f"  Total: {id_stats.total}")
        print(f"  Active: {id_stats.active}")
        print(f"  Revoked: {id_stats.revoked}")
        print(f"  Expiring soon: {id_stats.expiring_soon}")

        # 7. Risk assessment for a specific agent
        print("\n=== Risk Assessment (agent-001) ===")
        try:
            risk = client.compliance.assess_risk("agent-001")
            print(f"  Score: {risk.score}")
            print(f"  Level: {risk.level}")
            print(f"  Toxic violations: {risk.toxic_violations}")
            print(f"  Boundary crossings: {risk.boundary_crossings}")
        except Exception as e:
            print(f"  Could not assess: {e}")

        # 8. Graph stats
        print("\n=== Graph Stats ===")
        graph = client.enforcement.get_graph_stats()
        print(f"  {graph}")

        # 9. Kill switch history
        print("\n=== Recent Kill Switch Activity ===")
        history = client.killswitch.get_history()
        if history:
            for entry in history[:3]:
                print(f"  [{entry.created_at}] {entry.kill_type}: {entry.reason}")
        else:
            print("  No kill switch activity")

        # 10. Recent events
        print("\n=== Recent Events ===")
        events = client.events.list(limit=5)
        for event in events:
            print(f"  [{event.status}] {event.event_type} ({event.created_at})")


if __name__ == "__main__":
    main()
