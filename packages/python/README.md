# KSwitch Python SDK

Python client for the KSwitch Agent Trust Control Plane.

## Install

```sh
pip install kswitch-sdk
```

For local development:

```sh
pip install -e packages/python
```

## Usage

```python
from kswitch import KSwitchClient

client = KSwitchClient.from_env()
agent = client.governance.register_agent(
    display_name="customer-onboarding-v1",
    record_type="AGENT",
    risk_tier="tier_2",
    owning_division="Retail Banking",
    owning_team="onboarding-platform",
)
```
