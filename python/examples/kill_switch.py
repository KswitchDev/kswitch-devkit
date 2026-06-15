#!/usr/bin/env python3
"""Example: Kill switch operations with blast radius preview.

Usage:
    python kill_switch.py
"""

from kswitch import KSwitchClient


def main():
    with KSwitchClient(base_url="https://localhost:5001", token="your-token", verify_ssl=False) as client:
        agent_ids = ["agent-001", "agent-002"]

        # 1. Preview blast radius before killing
        print("Blast radius preview:")
        blast = client.enforcement.get_blast_radius(agent_ids=agent_ids)
        print(f"  Target agents: {blast.agent_ids}")
        print(f"  Affected agents: {blast.affected_agents}")
        print(f"  Affected MCPs: {blast.affected_mcps}")
        print(f"  Total impact: {blast.total_impact}")

        # 2. Targeted kill switch
        print("\nExecuting targeted kill switch...")
        result = client.killswitch.targeted(
            agent_ids=agent_ids,
            reason="Detected unauthorized data exfiltration",
            initiated_by="security-team@company.com",
        )
        print(f"  Suspended: {result.suspended}")
        print(f"  SPIFFE revoked: {result.spiffe_revoked}")
        print(f"  Service identities revoked: {result.service_identities_revoked}")

        # 3. Blanket kill switch (requires 2 approvals)
        print("\nInitiating blanket kill switch...")
        blanket = client.killswitch.blanket_initiate(
            reason="Critical security vulnerability in shared library",
            scope="all_tier_3",
            initiated_by="ciso@company.com",
        )
        print(f"  Blanket request ID: {blanket.id}")
        print(f"  Status: {blanket.status}")
        print(f"  Awaiting approvals...")

        # Approve the blanket kill (normally done by a different person)
        # client.killswitch.blanket_approve(blanket.id)

        # 4. Auto kill switch config
        print("\nAuto kill switch configuration:")
        config = client.killswitch.get_auto_config()
        print(f"  Enabled: {config.enabled}")
        print(f"  Threshold: {config.threshold}")
        print(f"  Require approval: {config.require_approval}")

        # 5. History
        print("\nKill switch history:")
        history = client.killswitch.get_history()
        for entry in history[:5]:
            print(f"  [{entry.created_at}] {entry.kill_type}: {entry.reason}")

        # 6. Violations
        print("\nKill switch violations:")
        violations = client.killswitch.get_violations()
        print(f"  {violations}")


if __name__ == "__main__":
    main()
