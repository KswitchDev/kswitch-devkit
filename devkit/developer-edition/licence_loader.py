"""Developer Edition entitlement overlay.

This module is bind-mounted over ``app/licence/loader.py`` by the local
devkit compose file. It deliberately does not read a customer licence JWS.

The production image still contains the normal fail-closed licence verifier.
Only the Developer Edition compose path shadows the loader and returns a fixed,
non-time-boxed local entitlement so the existing server-side capacity decorators
continue to enforce Developer Edition caps in official unmodified artefacts.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from app.licence.verifier import (
    LicenceError,
    LicenceState,
    VerifiedLicence,
    Verifier,
)


DEVELOPER_LIMITS: dict[str, int] = {
    "agents": 10,
    "mcps": 10,
    "tools": 100,
    "skills": 100,
}


@dataclass(frozen=True)
class DeveloperEntitlement:
    """Small compatibility object matching the licence consumers' needs."""

    claims: dict[str, Any] = field(default_factory=dict)
    kid: str = "kswitch-developer-edition-local"
    fingerprint_match: bool = True
    clock_rollback_detected: bool = False
    raw_token: str = field(default="developer-edition-no-jws", repr=False)

    def __post_init__(self) -> None:
        if self.claims:
            return
        now = int(time.time())
        object.__setattr__(
            self,
            "claims",
            {
                "iss": "kswitch.ai",
                "sub": "developer-local",
                "iat": now,
                "nbf": now,
                "exp": 4_102_444_800,  # 2100-01-01T00:00:00Z
                "edition": "developer",
                "limits": dict(DEVELOPER_LIMITS),
                "features": ["developer-edition", "local-only", "workload-identity"],
                "support": {"commercial_contact": "hello@kswitch.io"},
                "fingerprint": {"algorithm": "none", "value": "developer-edition"},
            },
        )

    @property
    def effective_now(self) -> int:
        return int(time.time())

    @property
    def iss(self) -> str:
        return str(self.claims["iss"])

    @property
    def sub(self) -> str:
        return str(self.claims["sub"])

    @property
    def exp(self) -> int:
        return int(self.claims["exp"])

    @property
    def nbf(self) -> int:
        return int(self.claims["nbf"])

    @property
    def edition(self) -> str:
        return str(self.claims["edition"])

    @property
    def limits(self) -> dict[str, int]:
        return dict(self.claims["limits"])

    @property
    def features(self) -> list[str]:
        return list(self.claims.get("features", []))

    @property
    def support(self) -> dict[str, str]:
        return dict(self.claims.get("support", {}))

    @property
    def fingerprint_claim(self) -> dict[str, str]:
        return dict(self.claims["fingerprint"])

    def is_expired(self) -> bool:
        return False

    def is_read_only(self) -> bool:
        return False

    def seconds_until_expiry(self) -> int:
        return self.exp - self.effective_now


_ENTITLEMENT = DeveloperEntitlement()


def current_licence() -> DeveloperEntitlement:
    return _ENTITLEMENT


def current_state() -> str:
    return LicenceState.VALID


def reload_now(reset_path: bool = False) -> None:
    return None


__all__ = [
    "DEVELOPER_LIMITS",
    "DeveloperEntitlement",
    "LicenceError",
    "LicenceState",
    "VerifiedLicence",
    "Verifier",
    "current_licence",
    "current_state",
    "reload_now",
]
