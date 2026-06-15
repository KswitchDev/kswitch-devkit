#!/usr/bin/env python3
"""Example: Register an agent, evaluate toxic combos, and approve.

Usage:
    export KSWITCH_TOKEN="your-token"
    python register_agent.py
"""

from kswitch import KSwitchClient, NotFoundError, ValidationError

BASE_URL = "https://localhost:5001"


def main():
    with KSwitchClient(base_url=BASE_URL, token="your-token", verify_ssl=False) as client:
        # 1. Register a new agent
        print("Registering agent...")
        agent = client.governance.register_agent(
            display_name="data-pipeline-agent",
            record_type="AGENT",
            risk_tier="tier_2",
            owning_division="engineering",
            owning_team="data-platform",
            description="Processes ETL pipelines with database access",
            environment="production",
            source_repo="https://github.com/myorg/data-pipeline",
            framework="langchain",
            data_classification="confidential",
        )
        print(f"  Agent registered: {agent.id}")
        print(f"  Status: {agent.status}")

        # 2. Assign skills
        print("\nAssigning skills...")
        client.governance.assign_skills(
            agent.id,
            skills=[
                {"skill_id": "database-read", "level": "full"},
                {"skill_id": "api-call", "level": "restricted"},
            ],
        )
        print("  Skills assigned")

        # 3. Evaluate toxic combos
        print("\nEvaluating toxic combinations...")
        toxic_result = client.compliance.evaluate_toxic_combos(agent.id)
        if toxic_result.clean:
            print("  No toxic combinations found")
        else:
            print(f"  VIOLATIONS FOUND: {len(toxic_result.violations)}")
            for v in toxic_result.violations:
                print(f"    - {v.rule_name} (severity: {v.severity})")

        # 4. Check approval criteria
        print("\nChecking approval criteria...")
        criteria = client.governance.get_approval_criteria(agent.id)
        print(f"  All criteria met: {criteria.all_met}")
        for c in criteria.criteria:
            print(f"    - {c.get('name')}: {'met' if c.get('met') else 'NOT MET'}")

        # 5. Approve if clean
        if toxic_result.clean and criteria.all_met:
            print("\nApproving agent...")
            client.governance.approve(
                agent.id,
                reviewed_by="admin@company.com",
                jira_ticket="GOV-1234",
            )
            print("  Agent approved!")
        else:
            print("\n  Agent cannot be approved yet — resolve issues first")

        # 6. Create SPIFFE identity
        print("\nCreating SPIFFE identity...")
        spiffe = client.identity.create_spiffe(agent.id)
        print(f"  SPIFFE ID: {spiffe.spiffe_id}")

        # 7. Verify final state
        final = client.governance.get_agent(agent.id)
        print(f"\nFinal agent state: {final.status}")


if __name__ == "__main__":
    main()
