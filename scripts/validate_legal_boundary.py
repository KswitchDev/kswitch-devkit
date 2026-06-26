#!/usr/bin/env python3
"""Validate the public DevKit legal/licence boundary.

This is intentionally static and dependency-free so CI can run it before any
SDK package install. It catches the failures that matter most for EP-227:
missing legal files, missing Developer Edition assent, SDK licence drift, and
copy that could imply the restricted runtime is open source or commercially
usable.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "LICENSE.md",
    "COMMERCIAL-USE.md",
    "NOTICE",
    "PRIVACY.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "DEPENDENCY-LICENSE-POLICY.md",
    "TRADEMARKS.md",
    "THIRD-PARTY-NOTICES.md",
    "RELEASE-LEGAL-CHECKLIST.md",
    "LICENSES/Apache-2.0.txt",
    "LICENSES/KSWITCH-DEVELOPER-EDITION-LICENSE.md",
    "reports/ep227/WEBSITE-HANDOFF.md",
]

TEXT_CHECKS = {
    "LICENSE.md": [
        "Developer Edition is not open source",
        "Commercial use requires a separate agreement",
        "python/",
        "typescript/",
        "go/",
        "mcp-server/",
        "devkit/",
    ],
    "COMMERCIAL-USE.md": [
        "Requires A Separate KSwitch Agreement",
        "internal business operations",
        "revenue-generating use",
    ],
    "LICENSES/KSWITCH-DEVELOPER-EDITION-LICENSE.md": [
        "source-available, non-commercial",
        "It is not an open-source",
        "production deployment",
        "internal business operations",
        "customer-facing use",
        "managed-service use",
        "revenue-generating use",
        "Agents | 10",
        "MCP servers | 10",
        "Tools | 100",
        "Skills | 100",
    ],
    "README.md": [
        "source-available",
        "not open source",
        "Commercial use requires a separate written agreement",
        "KSWITCH_ACCEPT_DEVELOPER_EDITION_LICENSE=1",
    ],
    "devkit/README.md": [
        "source-available, non-commercial",
        "not open source",
        "KSWITCH_ACCEPT_DEVELOPER_EDITION_LICENSE=1",
    ],
    "devkit/.env.example": [
        "KSWITCH_ACCEPT_DEVELOPER_EDITION_LICENSE=",
        "not open source",
        "requires a separate written",
    ],
    "devkit/Makefile": [
        "KSWITCH_ACCEPT_DEVELOPER_EDITION_LICENSE=1",
        "licence-terms",
        "Commercial use",
    ],
    "reports/ep227/WEBSITE-HANDOFF.md": [
        "source-available",
        "not open source",
        "KSWITCH_ACCEPT_DEVELOPER_EDITION_LICENSE=1",
        "https://kswitch.io/pages/devkit.html",
    ],
}


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def assert_required_files() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing required legal files: {', '.join(missing)}")


def assert_text_checks() -> None:
    for path, needles in TEXT_CHECKS.items():
        text = read(path)
        missing = [needle for needle in needles if needle not in text]
        if missing:
            fail(f"{path} missing required text: {', '.join(missing)}")


def assert_sdk_metadata() -> None:
    pyproject = read("python/pyproject.toml")
    if 'license = "Apache-2.0"' not in pyproject:
        fail("python/pyproject.toml must declare Apache-2.0")
    if "License :: OSI Approved :: Apache Software License" not in pyproject:
        fail("python/pyproject.toml classifier must declare Apache Software License")
    if not read("python/LICENSE").startswith("Apache License"):
        fail("python/LICENSE must be Apache-2.0")

    package = json.loads(read("typescript/package.json"))
    if package.get("license") != "Apache-2.0":
        fail("typescript/package.json must declare Apache-2.0")

    mcp_project = read("mcp-server/pyproject.toml")
    if 'license = "Apache-2.0"' not in mcp_project:
        fail("mcp-server/pyproject.toml must declare Apache-2.0")

    go_licence = read("go/LICENSE")
    if "Apache License" not in go_licence:
        fail("go/LICENSE must be Apache-2.0")


def assert_no_confusing_runtime_claims() -> None:
    checked = [
        "README.md",
        "devkit/README.md",
        "docs/free-for-life-positioning.md",
        "devkit/.env.example",
    ]
    open_source_runtime = re.compile(r"Developer Edition[^.\n]{0,120}open source", re.IGNORECASE)
    commercial_runtime = re.compile(r"Developer Edition[^.\n]{0,120}commercial use allowed", re.IGNORECASE)
    for path in checked:
        text = read(path)
        if open_source_runtime.search(text):
            fail(f"{path} appears to call Developer Edition open source")
        if commercial_runtime.search(text):
            fail(f"{path} appears to allow commercial Developer Edition use")


def main() -> int:
    assert_required_files()
    assert_text_checks()
    assert_sdk_metadata()
    assert_no_confusing_runtime_claims()
    print("legal-boundary: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
