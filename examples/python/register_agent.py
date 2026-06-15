from kswitch import KSwitchClient


def main() -> None:
    client = KSwitchClient.from_env()
    agent = client.governance.register_agent(
        display_name="customer-onboarding-v1",
        record_type="AGENT",
        risk_tier="tier_2",
        owning_division="Retail Banking",
        owning_team="onboarding-platform",
    )
    client.governance.connect_mcps(agent["id"], mcp_ids=["mcp-kyc", "mcp-customer-data"])
    print(agent["id"])


if __name__ == "__main__":
    main()

