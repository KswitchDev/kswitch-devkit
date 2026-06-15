"""KSwitch Python SDK — DenyReason enum (EP-050 W4 parity with server).

Usage::

    from kswitch.deny_reason import DenyReason, parse_deny_reason

    deny = parse_deny_reason(response.get("deny_reason"))
    if deny is DenyReason.UNAVAILABLE:
        # control-plane is down — back off and retry
        ...

Forward compatibility: unknown server values fall through to
``DenyReason.UNKNOWN`` rather than raising.  This lets the server roll out
new categories before every SDK pins a matching release.

Wire parity
-----------
Matches ``app/enforcement/reason_class.py::DenyReason`` (server).  The five
values are intentionally a small, stable set; adding a new value requires a
coordinated server-SDK rollout documented in the EP-050 closure EP.
"""
from __future__ import annotations

import enum
from typing import Any


class DenyReason(str, enum.Enum):
    """Semantic category of an enforcement deny decision.

    String-valued — serialises directly to JSON.
    """

    POLICY = "POLICY"
    GOVERNANCE = "GOVERNANCE"
    UNAVAILABLE = "UNAVAILABLE"
    VALIDATION = "VALIDATION"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, raw: Any) -> "DenyReason":
        """Parse any input into a DenyReason; unknown values → UNKNOWN."""
        if isinstance(raw, cls):
            return raw
        if not isinstance(raw, str):
            return cls.UNKNOWN
        try:
            return cls(raw.upper())
        except ValueError:
            return cls.UNKNOWN


def parse_deny_reason(raw: Any) -> DenyReason:
    """Module-level convenience alias for :meth:`DenyReason.parse`."""
    return DenyReason.parse(raw)


__all__ = ["DenyReason", "parse_deny_reason"]
