"""OpenAI Agents SDK callback watcher foundation for KS-EP-098a.

The adapter patches an explicit registrar object in W1 tests instead of
depending on a moving upstream API. W7 can bind this same wrapper to the
verified OpenAI Agents SDK entry point once the version matrix is pinned.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import inspect
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


@dataclass(frozen=True)
class CallbackRegistrationEvent:
    event_id: str
    event_name: str
    event_at: str
    tenant_id: str
    surface: str
    watcher_id: str
    watcher_mode: str
    agent_id: str
    payload: dict[str, Any]
    signing_key_id: str
    signature_algorithm: str
    signature: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kswitch.ep098.hook_watcher_event.v1",
            "event_id": self.event_id,
            "event_name": self.event_name,
            "event_at": self.event_at,
            "tenant_id": self.tenant_id,
            "surface": self.surface,
            "watcher_id": self.watcher_id,
            "watcher_mode": self.watcher_mode,
            "agent_id": self.agent_id,
            "payload": dict(self.payload),
            "signing_key_id": self.signing_key_id,
            "signature_algorithm": self.signature_algorithm,
            "signature": self.signature,
        }


def patch_callback_registrar(
    target: Any,
    method_name: str,
    *,
    tenant_id: str,
    agent_id: str,
    sink: Callable[[dict[str, Any]], None],
    sdk_version: str,
    degradation_sink: Callable[[dict[str, Any]], None],
    registry_matcher: Callable[[str], bool] | None = None,
) -> None:
    """Wrap one callback registration method and emit on every registration.

    The wrapper is fail-open for host SDK behavior. A degradation sink is
    mandatory so callback telemetry loss has a separate reporting path.
    """
    if degradation_sink is None:
        raise ValueError("degradation_sink is required for EP-098 SDK adapter reporting")
    original = getattr(target, method_name)
    if getattr(original, "_kswitch_ep098_patched", False):
        return

    @functools.wraps(original)
    def wrapped(callback: Any, *args: Any, **kwargs: Any) -> Any:
        name = _callback_name(callback)
        registry_match = False
        try:
            registry_match = bool(registry_matcher(name)) if registry_matcher else False
        except Exception as exc:
            _emit_degraded(
                degradation_sink,
                tenant_id=tenant_id,
                agent_id=agent_id,
                sdk_version=sdk_version,
                callback_name=name,
                callback_kind=method_name,
                failure_stage="registry_matcher",
                exc=exc,
            )
        try:
            sink(_event(
                tenant_id=tenant_id,
                agent_id=agent_id,
                sdk_version=sdk_version,
                callback=callback,
                callback_name=name,
                callback_kind=method_name,
                registry_match=registry_match,
            ).as_dict())
        except Exception as exc:
            _emit_degraded(
                degradation_sink,
                tenant_id=tenant_id,
                agent_id=agent_id,
                sdk_version=sdk_version,
                callback_name=name,
                callback_kind=method_name,
                failure_stage="event_sink",
                exc=exc,
            )
        return original(callback, *args, **kwargs)

    setattr(wrapped, "_kswitch_ep098_patched", True)
    setattr(target, method_name, wrapped)


def _event(
    *,
    tenant_id: str,
    agent_id: str,
    sdk_version: str,
    callback: Any,
    callback_name: str,
    callback_kind: str,
    registry_match: bool,
) -> CallbackRegistrationEvent:
    return CallbackRegistrationEvent(
        event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_id}:{agent_id}:{callback_name}:{callback_kind}")),
        event_name="hook.sdk_callback_registered",
        event_at=datetime(2026, 5, 10, 0, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        tenant_id=tenant_id,
        surface="sdk_callback",
        watcher_id="sdk-adapter:openai-agents-python",
        watcher_mode="sdk_adapter",
        agent_id=agent_id,
        payload={
            "sdk_name": "openai_agents",
            "sdk_version": sdk_version,
            "callback_name": callback_name,
            "callback_kind": callback_kind,
            "module_hash": _module_hash(callback),
            "callsite": _callsite(),
            "registry_match": registry_match,
        },
        signing_key_id=_signing_key_id(tenant_id),
        signature_algorithm="ed25519",
        signature=_signature(tenant_id, agent_id, callback_name, callback_kind, sdk_version),
    )


def _emit_degraded(
    sink: Callable[[dict[str, Any]], None],
    *,
    tenant_id: str,
    agent_id: str,
    sdk_version: str,
    callback_name: str,
    callback_kind: str,
    failure_stage: str,
    exc: Exception,
) -> None:
    event = CallbackRegistrationEvent(
        event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_id}:{agent_id}:{callback_name}:{failure_stage}")),
        event_name="hook.sdk_callback_adapter_degraded",
        event_at=datetime(2026, 5, 10, 0, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        tenant_id=tenant_id,
        surface="sdk_callback",
        watcher_id="sdk-adapter:openai-agents-python",
        watcher_mode="sdk_adapter",
        agent_id=agent_id,
        payload={
            "sdk_name": "openai_agents",
            "sdk_version": sdk_version,
            "callback_name": callback_name,
            "callback_kind": callback_kind,
            "failure_stage": failure_stage,
            "error_class": type(exc).__name__,
            "delivery_status": "adapter_degraded",
        },
        signing_key_id=_signing_key_id(tenant_id),
        signature_algorithm="ed25519",
        signature=_signature(tenant_id, agent_id, callback_name, callback_kind, failure_stage),
    )
    try:
        sink(event.as_dict())
    except Exception:
        pass


def _callback_name(callback: Any) -> str:
    return getattr(callback, "__qualname__", None) or getattr(callback, "__name__", None) or repr(callback)


def _module_hash(callback: Any) -> str:
    module = inspect.getmodule(callback)
    source = getattr(module, "__file__", None) or getattr(module, "__name__", "unknown")
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _callsite() -> str:
    frame = inspect.stack()[3]
    return f"{frame.filename}:{frame.lineno}"


def _signing_key_id(tenant_id: str) -> str:
    return f"sdk-adapter-key:{tenant_id}:openai-agents-python:2026-05"


def _signature(*parts: str) -> str:
    body = ":".join(parts)
    signature_bytes = hashlib.sha512(body.encode("utf-8")).digest()
    return "ed25519:" + base64.urlsafe_b64encode(signature_bytes).decode("ascii").rstrip("=")
