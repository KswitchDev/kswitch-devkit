#!/usr/bin/env python3
"""Static checks for the public Developer Edition devkit.

These checks intentionally avoid importing the app image. They validate the
repository artefacts that make the free local path licence-free and hard-capped.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LIMITS = {
    "agents": 10,
    "mcps": 10,
    "tools": 100,
    "skills": 100,
}


def fail(message: str) -> None:
    print(f"FATAL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def verify_limits() -> None:
    tree = ast.parse(read("developer-edition/licence_loader.py"))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "DEVELOPER_LIMITS":
            limits = ast.literal_eval(node.value)
            if limits != EXPECTED_LIMITS:
                fail(f"Developer Edition limits changed: {limits!r}")
            return
    fail("DEVELOPER_LIMITS constant not found")


def verify_compose_overlay() -> None:
    compose = read("docker-compose.yml")
    required = (
        "${KSWITCH_IMAGE:?KSWITCH_IMAGE required",
        "${KSWITCH_SPIRE_AGENT_WRAPPER_IMAGE:?KSWITCH_SPIRE_AGENT_WRAPPER_IMAGE required",
    )
    for needle in required:
        if needle not in compose:
            fail(f"docker-compose.yml missing required Developer Edition marker: {needle}")

    forbidden_patterns = {
        "licence bind mount": r"\./licen[cs]e:/var/lib/kswitch",
        "licence path env": r"\bLICEN[CS]E_PATH\b",
        "developer loader bind mount": r"developer-edition/licen[cs]e_loader\.py:/",
    }
    for label, pattern in forbidden_patterns.items():
        if re.search(pattern, compose, flags=re.IGNORECASE):
            fail(f"docker-compose.yml still contains {label}")
    for private_ref in (
        "ghcr.io/maxcope-alt/kswitch:",
        "ghcr.io/maxcope-alt/kswitch-spire-agent-wrapper:",
    ):
        if private_ref in compose:
            fail(f"docker-compose.yml still references private image namespace: {private_ref}")


def verify_public_image_defaults() -> None:
    env_example = read(".env.example")
    expected = (
        "KSWITCH_IMAGE=ghcr.io/kswitchdev/kswitch-developer:v1.36-pg",
        "KSWITCH_SPIRE_AGENT_WRAPPER_IMAGE=ghcr.io/kswitchdev/kswitch-spire-agent-wrapper:1.10",
    )
    for line in expected:
        if line not in env_example:
            fail(f".env.example missing public image default: {line}")


def verify_live_docs() -> None:
    live_paths = [
        ".env.example",
        "README.md",
        "TROUBLESHOOTING.md",
        "Makefile",
        "developer-edition/licence_loader.py",
    ]
    forbidden = [
        "renewal_contact",
        "licence/licence.jws",
        "scripts/licence_info.py",
        "LICENCE_PATH",
    ]
    for path in live_paths:
        text = read(path)
        for needle in forbidden:
            if needle in text:
                fail(f"{path} contains retired Developer Edition term: {needle}")


def main() -> None:
    verify_limits()
    verify_compose_overlay()
    verify_public_image_defaults()
    verify_live_docs()
    print("Developer Edition static checks passed")


if __name__ == "__main__":
    main()
