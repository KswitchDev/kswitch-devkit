#!/usr/bin/env python3
"""EP-227 public release validation.

This command is intentionally conservative. It should fail until every release
gate has evidence and counsel/product/security approvals are complete.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "ep227" / "ep227-validation-report.json"

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
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/config.yml",
]

PUBLIC_TEXT_GLOBS = [
    "README.md",
    "COMMERCIAL-USE.md",
    "PRIVACY.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "TRADEMARKS.md",
    "THIRD-PARTY-NOTICES.md",
    "docs/*.md",
    "devkit/README.md",
    "devkit/TROUBLESHOOTING.md",
    "python/README.md",
    "typescript/README.md",
    "go/README.md",
]

FORBIDDEN_PUBLIC_PATTERNS = {
    "free forever": "Use no-scheduled-expiry wording, not lifetime-rights wording.",
    "free for life": "Use no-scheduled-expiry wording, not lifetime-rights wording.",
    "hard-capped": "Say official unmodified artefacts enforce caps.",
    "hard capped": "Say official unmodified artefacts enforce caps.",
    "security-first": "Avoid unqualified security claims.",
    "security first": "Avoid unqualified security claims.",
    "production ready": "Developer Edition is not a production-ready claim.",
    "enterprise ready": "Developer Edition is not an enterprise-ready claim.",
    "bank-grade": "Avoid unqualified regulated/security claims.",
    "zero trust": "Avoid unqualified architecture/compliance claims.",
}

FORBIDDEN_REPO_PATTERNS = {
    "DaveWalker": "Customer/pilot identifier must not be public.",
    "dev001": "Customer/pilot identifier must not be public.",
    "trial licence": "Developer Edition must not use trial posture.",
    "customer trial": "Developer Edition must not use trial posture.",
    "renewal_contact": "Developer Edition must not expose renewal language.",
    "copy(sessionStorage": "Do not instruct token extraction from browser storage.",
    "sessionStorage.getItem": "Do not instruct token extraction from browser storage.",
    "localStorage.getItem": "Do not instruct token extraction from browser storage.",
}

ALLOWED_DEFAULT_SERVICES = {
    "app",
    "app-init",
    "postgres",
    "keycloak",
    "keycloak-db",
    "opa",
    "falkordb",
    "valkey",
}

OPTIONAL_PROFILE_SERVICES = {
    "spire-server",
    "spire-agent",
}

EVIDENCE_FILES = [
    "reports/ep227/sdk-ip-boundary.csv",
    "reports/ep227/sdk-ip-boundary.md",
    "reports/ep227/public-claims-matrix.md",
    "reports/ep227/privacy-data-flow-review.md",
    "reports/ep227/export-sanctions-review.md",
    "reports/ep227/release-evidence-index.md",
    "reports/ep227/package-inspection.md",
]


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def add(failures: list[dict[str, str]], gate: str, path: str, message: str) -> None:
    failures.append({"gate": gate, "path": path, "message": message})


def check_required_files(failures: list[dict[str, str]]) -> None:
    for item in REQUIRED_FILES:
        if not (ROOT / item).is_file():
            add(failures, "G1", item, "Required legal/release-control file is missing.")


def check_public_claims(failures: list[dict[str, str]]) -> None:
    for pattern in PUBLIC_TEXT_GLOBS:
        for path in ROOT.glob(pattern):
            if not path.is_file():
                continue
            text = read_text(path).lower()
            for needle, message in FORBIDDEN_PUBLIC_PATTERNS.items():
                if needle in text:
                    add(failures, "G21", rel(path), f"{message} Matched: {needle!r}.")


def check_repo_sanitisation(failures: list[dict[str, str]]) -> None:
    ignored_parts = {".git", "node_modules", "dist", ".venv", "__pycache__"}
    excluded_files = {
        Path("scripts/validate_ep227_release.py"),
    }
    for path in ROOT.rglob("*"):
        if not path.is_file() or ignored_parts.intersection(path.parts):
            continue
        if path.relative_to(ROOT) in excluded_files:
            continue
        if path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".lock"}:
            continue
        text = read_text(path)
        for needle, message in FORBIDDEN_REPO_PATTERNS.items():
            if needle in text:
                add(failures, "G4/G7", rel(path), f"{message} Matched: {needle!r}.")


def check_python_licence(failures: list[dict[str, str]]) -> None:
    pyproject = ROOT / "python" / "pyproject.toml"
    if not pyproject.is_file():
        add(failures, "G2", "python/pyproject.toml", "Python package metadata missing.")
        return
    text = read_text(pyproject)
    if 'license = "Apache-2.0"' not in text:
        add(failures, "G2", "python/pyproject.toml", "Python SDK must declare Apache-2.0.")
    if "MIT License" in text or 'license = "MIT"' in text:
        add(failures, "G2", "python/pyproject.toml", "Python SDK still declares MIT.")
    licence = ROOT / "python" / "LICENSE"
    if not licence.is_file() or "Apache License" not in read_text(licence):
        add(failures, "G2", "python/LICENSE", "Python SDK licence file must be Apache-2.0.")


def parse_compose_services() -> set[str]:
    compose = ROOT / "devkit" / "docker-compose.yml"
    if not compose.is_file():
        return set()
    services: set[str] = set()
    in_services = False
    for line in read_text(compose).splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if not in_services:
            continue
        if line and not line.startswith((" ", "\t")):
            break
        match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if match:
            services.add(match.group(1))
    return services


def check_service_boundary(failures: list[dict[str, str]]) -> None:
    services = parse_compose_services()
    allowed = ALLOWED_DEFAULT_SERVICES | OPTIONAL_PROFILE_SERVICES
    disallowed = sorted(s for s in services if s not in allowed)
    if disallowed:
        add(
            failures,
            "G9/G19",
            "devkit/docker-compose.yml",
            "Services outside the EP-227 minimal/default or optional identity boundary: "
            + ", ".join(disallowed),
        )


def check_release_approval(failures: list[dict[str, str]]) -> None:
    checklist = ROOT / "RELEASE-LEGAL-CHECKLIST.md"
    if checklist.is_file() and "PENDING" in read_text(checklist):
        add(failures, "G12/G24/G26", rel(checklist), "Release legal checklist still has PENDING items.")


def check_evidence(failures: list[dict[str, str]]) -> None:
    for item in EVIDENCE_FILES:
        path = ROOT / item
        if not path.is_file():
            add(failures, "G15/G21/G23/G24/G27/G28", item, "Required EP-227 evidence file is missing.")
        elif "PENDING" in read_text(path) or "release blocked" in read_text(path).lower():
            add(failures, "G15/G21/G23/G24/G27/G28", item, "Required EP-227 evidence is still pending/blocking.")

    image_evidence = ROOT / "reports" / "ep227" / "images"
    if not image_evidence.is_dir():
        add(failures, "G14/G25", "reports/ep227/images", "Image/SBOM/redistribution evidence directory is missing.")
    elif not any(image_evidence.glob("image-sbom-*")):
        add(failures, "G14/G25", rel(image_evidence), "Image SBOM evidence is missing.")
    elif not any(image_evidence.glob("image-redistribution-rights-*")):
        add(failures, "G14/G25", rel(image_evidence), "Image redistribution-rights evidence is missing.")

    manifest = ROOT / "devkit" / "MANIFEST.json"
    if manifest.is_file():
        try:
            manifest_data = json.loads(read_text(manifest))
        except json.JSONDecodeError:
            add(failures, "G13", rel(manifest), "Devkit manifest is not valid JSON.")
        else:
            if manifest_data.get("release_blocked") or manifest_data.get("status") == "placeholder":
                add(failures, "G13", rel(manifest), "Devkit manifest is still a release-blocking placeholder.")
    else:
        add(failures, "G13", rel(manifest), "Devkit manifest is missing.")


def build_manifest() -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        files.append({"path": rel(path), "sha256": sha256(path)})
    return files


def main() -> int:
    failures: list[dict[str, str]] = []

    check_required_files(failures)
    check_public_claims(failures)
    check_repo_sanitisation(failures)
    check_python_licence(failures)
    check_service_boundary(failures)
    check_release_approval(failures)
    check_evidence(failures)

    report = {
        "status": "fail" if failures else "pass",
        "failure_count": len(failures),
        "failures": failures,
        "manifest": build_manifest(),
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if failures:
        print(f"EP-227 release validation failed with {len(failures)} blocker(s).")
        print(f"Report: {rel(REPORT)}")
        for failure in failures[:20]:
            print(f"- [{failure['gate']}] {failure['path']}: {failure['message']}")
        if len(failures) > 20:
            print(f"- ... {len(failures) - 20} more blocker(s) in the report")
        return 1

    print("EP-227 release validation passed.")
    print(f"Report: {rel(REPORT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
