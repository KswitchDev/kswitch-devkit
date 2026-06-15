#!/usr/bin/env python3
"""Developer Edition boot entitlement check.

The public local image does not read a customer JWS. It must boot only when the
baked Developer Edition loader returns the expected non-expiring local caps.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from app.licence.loader import current_licence, current_state  # noqa: E402


EXPECTED_LIMITS = {
    "agents": 10,
    "mcps": 10,
    "tools": 100,
    "skills": 100,
}


def main() -> int:
    lic = current_licence()
    if lic is None:
        print("  FATAL: Developer Edition entitlement missing.", file=sys.stderr)
        return 1
    if current_state() != "valid":
        print(f"  FATAL: Developer Edition state is {current_state()!r}.", file=sys.stderr)
        return 1
    if getattr(lic, "edition", None) != "developer":
        print(f"  FATAL: expected edition='developer', got {getattr(lic, 'edition', None)!r}.", file=sys.stderr)
        return 1
    if lic.limits != EXPECTED_LIMITS:
        print(f"  FATAL: Developer Edition limits changed: {lic.limits!r}.", file=sys.stderr)
        return 1
    print("  Developer Edition: local entitlement valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
