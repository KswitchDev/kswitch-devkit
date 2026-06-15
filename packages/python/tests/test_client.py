import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from kswitch import KSwitchClient


class FakeHeaders:
    def get_content_charset(self):
        return "utf-8"


class FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode("utf-8")
        self.headers = FakeHeaders()

    def read(self):
        return self._payload


class ClientTest(unittest.TestCase):
    def test_register_agent_request(self):
        captured = {}

        def transport(request, timeout):
            captured["url"] = request.full_url
            captured["method"] = request.get_method()
            captured["headers"] = dict(request.header_items())
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse({"id": "agent-123"})

        client = KSwitchClient(
            base_url="https://api.example.test",
            api_key="test-token",
            timeout=12,
            transport=transport,
        )

        result = client.governance.register_agent(
            display_name="customer-onboarding-v1",
            record_type="AGENT",
            risk_tier="tier_2",
            owning_division="Retail Banking",
            owning_team="onboarding-platform",
        )

        self.assertEqual(result, {"id": "agent-123"})
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["url"], "https://api.example.test/api/v1/agents/register")
        self.assertEqual(captured["timeout"], 12)
        self.assertEqual(captured["body"]["display_name"], "customer-onboarding-v1")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer test-token")

    def test_audit_events_filters_query(self):
        captured = {}

        def transport(request, timeout):
            captured["url"] = request.full_url
            return FakeResponse({"events": []})

        client = KSwitchClient(
            base_url="https://api.example.test",
            api_key="test-token",
            transport=transport,
        )

        client.audit.events(agent_id="agent-123", event_type="shadow_denied", limit=25)

        self.assertEqual(
            captured["url"],
            "https://api.example.test/api/v1/audit/events?agent_id=agent-123&event_type=shadow_denied&limit=25",
        )


if __name__ == "__main__":
    unittest.main()
