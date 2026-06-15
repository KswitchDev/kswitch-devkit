#!/usr/bin/env python3
"""Example: AuthZen evaluation — check if an agent can invoke a tool.

Usage:
    python evaluate_access.py
"""

from kswitch import KSwitchClient


def main():
    with KSwitchClient(base_url="https://localhost:5001", token="your-token", verify_ssl=False) as client:
        # Single evaluation
        print("Single AuthZen evaluation:")
        decision = client.authzen.evaluate(
            subject={"type": "agent", "id": "agent-001"},
            resource={"type": "tool", "id": "read-database"},
            action={"name": "invoke"},
            context={"environment": "production"},
        )
        print(f"  Decision: {'ALLOW' if decision.decision else 'DENY'}")
        print(f"  Context: {decision.context}")

        # Batch evaluation
        print("\nBatch AuthZen evaluation:")
        batch = client.authzen.evaluate_batch(
            evaluations=[
                {
                    "subject": {"type": "agent", "id": "agent-001"},
                    "resource": {"type": "tool", "id": "read-database"},
                    "action": {"name": "invoke"},
                },
                {
                    "subject": {"type": "agent", "id": "agent-001"},
                    "resource": {"type": "tool", "id": "write-database"},
                    "action": {"name": "invoke"},
                },
                {
                    "subject": {"type": "agent", "id": "agent-001"},
                    "resource": {"type": "tool", "id": "delete-records"},
                    "action": {"name": "invoke"},
                },
            ]
        )
        for i, eval_result in enumerate(batch.evaluations):
            print(f"  Evaluation {i + 1}: {'ALLOW' if eval_result.decision else 'DENY'}")

        # Search: what resources can this agent access?
        print("\nResource search:")
        resources = client.authzen.search_resource(
            subject={"type": "agent", "id": "agent-001"},
            action={"name": "invoke"},
        )
        for r in resources.results:
            print(f"  - {r}")

        # Search: what actions can this agent perform on a resource?
        print("\nAction search:")
        actions = client.authzen.search_action(
            subject={"type": "agent", "id": "agent-001"},
            resource={"type": "tool", "id": "read-database"},
        )
        for a in actions.results:
            print(f"  - {a}")

        # Cedar policy evaluation via policy engine
        print("\nDirect policy evaluation:")
        policy_decision = client.policy.evaluate(
            principal="agent::agent-001",
            action="invoke",
            resource="tool::read-database",
            context={"environment": "production"},
        )
        print(f"  Decision: {policy_decision.decision}")
        print(f"  Policies matched: {policy_decision.policies_matched}")

        # AuthZen discovery
        print("\nAuthZen discovery:")
        config = client.authzen.discovery()
        print(f"  Configuration: {config}")


if __name__ == "__main__":
    main()
