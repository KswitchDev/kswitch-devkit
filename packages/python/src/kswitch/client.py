from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping


JsonObject = dict[str, Any]
Transport = Callable[[urllib.request.Request, float], Any]


class KSwitchError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def _default_transport(request: urllib.request.Request, timeout: float) -> Any:
    return urllib.request.urlopen(request, timeout=timeout)


@dataclass(frozen=True)
class _RequestOptions:
    method: str
    path: str
    body: Mapping[str, Any] | None = None
    query: Mapping[str, Any] | None = None


class KSwitchClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        transport: Transport = _default_transport,
    ) -> None:
        auth_token = api_key or token
        if not base_url:
            raise ValueError("base_url is required")
        if not auth_token:
            raise ValueError("api_key or token is required")

        self.base_url = base_url.rstrip("/")
        self.api_key = auth_token
        self.timeout = timeout
        self._transport = transport
        self.governance = GovernanceClient(self)
        self.policy = PolicyClient(self)
        self.audit = AuditClient(self)
        self.tools = ToolsClient(self)
        self.kill_switch = KillSwitchClient(self)

    @classmethod
    def from_env(cls) -> "KSwitchClient":
        api_key = os.environ.get("KSWITCH_API_KEY") or os.environ.get("KSWITCH_TOKEN")
        if not api_key:
            raise ValueError("KSWITCH_API_KEY or KSWITCH_TOKEN is required")
        return cls(
            base_url=os.environ.get("KSWITCH_BASE_URL") or os.environ.get("KSWITCH_URL", "https://api.kswitch.io"),
            api_key=api_key,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        query: Mapping[str, Any] | None = None,
    ) -> Any:
        return self._request(_RequestOptions(method=method, path=path, body=body, query=query))

    def _request(self, options: _RequestOptions) -> Any:
        url = self._build_url(options.path, options.query)
        payload = None if options.body is None else json.dumps(options.body).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            method=options.method.upper(),
            headers={
                "authorization": f"Bearer {self.api_key}",
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "kswitch-python/0.1.0",
            },
        )

        try:
            response = self._transport(request, self.timeout)
            data = response.read()
            if not data:
                return None
            charset = response.headers.get_content_charset() or "utf-8"
            return json.loads(data.decode(charset))
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc)
            raise KSwitchError(
                f"KSwitch API request failed with status {exc.code}",
                status=exc.code,
                body=body,
            ) from exc
        except urllib.error.URLError as exc:
            raise KSwitchError(f"KSwitch API request failed: {exc.reason}") from exc

    def _build_url(self, path: str, query: Mapping[str, Any] | None = None) -> str:
        normalized_path = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url}{normalized_path}"
        if not query:
            return url

        encoded = urllib.parse.urlencode(
            {
                key: value
                for key, value in query.items()
                if value is not None
            },
            doseq=True,
        )
        return f"{url}?{encoded}" if encoded else url


class GovernanceClient:
    def __init__(self, client: KSwitchClient) -> None:
        self._client = client

    def register_agent(
        self,
        *,
        display_name: str,
        record_type: str,
        risk_tier: str,
        owning_division: str,
        owning_team: str,
        skills: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        return self._client.request(
            "POST",
            "/api/v1/agents/register",
            body={
                "display_name": display_name,
                "record_type": record_type,
                "risk_tier": risk_tier,
                "owning_division": owning_division,
                "owning_team": owning_team,
                "skills": skills or [],
                "metadata": dict(metadata or {}),
            },
        )

    def connect_mcps(self, agent_id: str, *, mcp_ids: list[str]) -> JsonObject:
        return self._client.request(
            "POST",
            f"/api/v1/agents/{urllib.parse.quote(agent_id, safe='')}/mcps",
            body={"mcp_ids": mcp_ids},
        )

    def evaluate_toxic_combos(self, agent_id: str) -> JsonObject:
        return self._client.request(
            "POST",
            f"/api/v1/agents/{urllib.parse.quote(agent_id, safe='')}/evaluate-toxic-combos",
        )

    def approve_agent(self, agent_id: str, *, second_line_ref: str | None = None) -> JsonObject:
        body: JsonObject = {}
        if second_line_ref:
            body["second_line_ref"] = second_line_ref
        return self._client.request(
            "POST",
            f"/api/v1/agents/{urllib.parse.quote(agent_id, safe='')}/approve",
            body=body,
        )


class PolicyClient:
    def __init__(self, client: KSwitchClient) -> None:
        self._client = client

    def update(self, policy_id: str, **fields: Any) -> JsonObject:
        return self._client.request(
            "PATCH",
            f"/api/v1/policies/{urllib.parse.quote(policy_id, safe='')}",
            body=fields,
        )


class AuditClient:
    def __init__(self, client: KSwitchClient) -> None:
        self._client = client

    def events(
        self,
        *,
        agent_id: str | None = None,
        event_type: str | None = None,
        limit: int | None = None,
    ) -> JsonObject:
        return self._client.request(
            "GET",
            "/api/v1/audit/events",
            query={"agent_id": agent_id, "event_type": event_type, "limit": limit},
        )


class ToolsClient:
    def __init__(self, client: KSwitchClient) -> None:
        self._client = client

    def list(self) -> JsonObject:
        return self._client.request("GET", "/api/v1/tools-catalog")


class KillSwitchClient:
    def __init__(self, client: KSwitchClient) -> None:
        self._client = client

    def targeted_kill_switch(self, agent_id: str, *, reason: str) -> JsonObject:
        return self._client.request(
            "POST",
            f"/api/v1/agents/{urllib.parse.quote(agent_id, safe='')}/kill-switch",
            body={"reason": reason},
        )

    def suspend_agent(self, agent_id: str, *, reason: str) -> JsonObject:
        return self._client.request(
            "POST",
            f"/api/v1/agents/{urllib.parse.quote(agent_id, safe='')}/suspend",
            body={"reason": reason},
        )

    def reactivate_agent(self, agent_id: str) -> JsonObject:
        return self._client.request(
            "POST",
            f"/api/v1/agents/{urllib.parse.quote(agent_id, safe='')}/reactivate",
        )


def _read_error_body(exc: urllib.error.HTTPError) -> Any:
    raw = exc.read()
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return raw.decode("utf-8", errors="replace")
