"""Policy bundle cache — Ed25519 signature verification, stale handling, L2b rule evaluation.
Bundle storage: ~/.kswitch/policy-bundle.json
Public key:     KSWITCH_BUNDLE_PUBKEY_FILE, ~/.kswitch/bundle-signing-pubkey.pem,
                then kswitch_mcp/keys/bundle-signing-pubkey.pem
                (absent/placeholder in dev = skip verify)
Stale handling: stale+waivable → None; stale+non-waivable → PartialBundle (enforce anyway)
EP-072, §5.1 L2b/L3 layers.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import ClassVar

from kswitch_mcp.local_rules import LocalAccessDecision

# ---------------------------------------------------------------------------
# cryptography import — optional; absent in dev (skip verify)
# ---------------------------------------------------------------------------

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    log_msg = (
        "policy_cache: 'cryptography' package is not installed. "
        "Ed25519 signature verification is DISABLED. "
        "Install with: pip install cryptography"
    )
    # We cannot use the module-level logger here (not yet defined), so use
    # the root logger directly.
    import logging as _logging_bootstrap

    _logging_bootstrap.getLogger(__name__).warning(log_msg)

log = logging.getLogger(__name__)


def _urllib_ssl_context(verify_ssl: bool | str = True):
    """Return a urllib SSL context for bool/path verification settings."""
    if verify_ssl is True:
        return None
    import ssl

    if verify_ssl is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    return ssl.create_default_context(cafile=str(verify_ssl))


# ---------------------------------------------------------------------------
# PolicyBundle dataclass
# ---------------------------------------------------------------------------


@dataclass
class PolicyBundle:
    """Signed policy bundle downloaded from the KSwitch control plane.

    ``tc_rules`` — toxic-combo rules (display/reference; TC evaluation is
    done server-side by the control plane).
    ``lu_rules`` — L2b LU rules (LU-004+); empty until first
    ``kswitch policy pull``.
    """

    version: str
    issued_at: str           # ISO-8601
    expires_at: str | None   # ISO-8601 — hard expiry, overrides MAX_BUNDLE_AGE_DAYS
    waivable: bool           # If False, stale bundle still enforces (PartialBundle mode)
    tc_rules: list[dict]     # Toxic-combo rules from control plane
    lu_rules: list[dict]     # L2b LU rules (LU-004+)
    issued_by: str = ""
    signature: str = ""      # Base64-encoded Ed25519 signature over canonical JSON


# ---------------------------------------------------------------------------
# BundleLoadResult enum
# ---------------------------------------------------------------------------


class BundleLoadResult(str, Enum):
    NONE = "none"        # No bundle on disk
    BUNDLE = "bundle"    # Valid, non-stale bundle loaded
    PARTIAL = "partial"  # Stale, non-waivable: enforce tc_rules + lu_rules anyway
    INVALID = "invalid"  # Signature verification failed — treat as NONE


# ---------------------------------------------------------------------------
# PolicyCache class
# ---------------------------------------------------------------------------


class PolicyCache:
    """Cache for a locally stored, Ed25519-signed policy bundle.

    Typical lifecycle:
    1. ``load()`` is called once in ``_proxy_lifespan`` at startup.
    2. ``pull()`` is called periodically (or on demand) to refresh the bundle
       from the control plane.
    3. ``check()`` is called on every tool call to apply L2b LU rules.
    """

    _BUNDLE_PATH: ClassVar[Path] = Path.home() / ".kswitch" / "policy-bundle.json"
    _USER_PUBKEY_PATH: ClassVar[Path] = Path.home() / ".kswitch" / "bundle-signing-pubkey.pem"
    _PACKAGE_PUBKEY_PATH: ClassVar[Path] = (
        Path(__file__).parent / "keys" / "bundle-signing-pubkey.pem"
    )
    # Back-compat for tests and callers that monkey-patch _PUBKEY_PATH.
    _PUBKEY_PATH: ClassVar[Path] = _PACKAGE_PUBKEY_PATH
    MAX_BUNDLE_AGE_DAYS: ClassVar[int] = 7

    def __init__(self) -> None:
        self._bundle: PolicyBundle | None = None
        self._partial: bool = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_utc(self, iso_str: str) -> datetime:
        """Parse an ISO-8601 UTC string to an aware datetime.

        Handles both 'Z' suffix and '+00:00' offset.
        """
        iso_str = iso_str.rstrip("Z")
        try:
            dt = datetime.fromisoformat(iso_str)
        except ValueError:
            # Last-resort: strip sub-second precision and retry.
            dt = datetime.fromisoformat(iso_str.split(".")[0])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _resolve_pubkey_path(self) -> Path | None:
        """Return the first usable bundle-signing public-key path.

        Resolution order:
        1. ``KSWITCH_BUNDLE_PUBKEY_FILE`` when set.
        2. ``~/.kswitch/bundle-signing-pubkey.pem`` downloaded by the CLI.
        3. Packaged fallback key for dev/test distributions.

        A comment-only placeholder is treated as absent so packaged wheels do
        not reject real policy bundles before an operator pins the org key.
        """
        candidates: list[Path] = []
        override = os.environ.get("KSWITCH_BUNDLE_PUBKEY_FILE", "").strip()
        if override:
            candidates.append(Path(override).expanduser())
        candidates.append(self._USER_PUBKEY_PATH)
        candidates.append(self._PUBKEY_PATH)

        seen: set[Path] = set()
        for path in candidates:
            if path in seen:
                continue
            seen.add(path)
            if not path.exists():
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                log.warning("policy_cache: failed to read public key %s: %s", path, exc)
                continue
            if "-----BEGIN PUBLIC KEY-----" not in raw:
                log.warning(
                    "policy_cache: public key at %s is not a PEM public key — "
                    "treating as absent.",
                    path,
                )
                continue
            return path
        return None

    def _verify_signature(self, bundle_dict: dict) -> bool:
        """Verify the Ed25519 signature on *bundle_dict*.

        Returns True if signature is valid (or pubkey absent in dev mode).
        Returns False on InvalidSignature.
        Logs critical on failure; logs warning if crypto library missing.
        """
        pubkey_path = self._resolve_pubkey_path()
        if pubkey_path is None:
            log.warning(
                "policy_cache: bundle-signing public key not found — "
                "signature verification SKIPPED (dev mode). "
                "Run `kswitch policy pull` against the control plane to pin "
                "~/.kswitch/bundle-signing-pubkey.pem before production use.",
            )
            return True

        if not _CRYPTO_AVAILABLE:
            log.warning(
                "policy_cache: 'cryptography' not installed — "
                "signature verification SKIPPED. "
                "Install cryptography to enable bundle signing."
            )
            return True

        sig_b64 = bundle_dict.get("signature", "")
        if not sig_b64:
            log.critical(
                "policy_cache: bundle has no signature field — treating as INVALID."
            )
            return False

        try:
            sig_bytes = base64.b64decode(sig_b64)
        except Exception as exc:
            log.critical(
                "policy_cache: failed to base64-decode bundle signature: %s", exc
            )
            return False

        # Build canonical JSON: exclude the signature field, sort keys.
        canonical_dict = {k: v for k, v in bundle_dict.items() if k != "signature"}
        canonical_bytes = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")

        try:
            pem_bytes = pubkey_path.read_bytes()
            public_key = load_pem_public_key(pem_bytes)
        except Exception as exc:
            log.critical(
                "policy_cache: failed to load public key from %s: %s",
                pubkey_path,
                exc,
            )
            return False

        if not isinstance(public_key, Ed25519PublicKey):
            log.critical(
                "policy_cache: public key at %s is not an Ed25519 key — "
                "got %s. Bundle treated as INVALID.",
                pubkey_path,
                type(public_key).__name__,
            )
            return False

        try:
            public_key.verify(sig_bytes, canonical_bytes)
            return True
        except InvalidSignature:
            log.critical(
                "policy_cache: Ed25519 signature verification FAILED — "
                "bundle rejected. This may indicate tampering."
            )
            return False
        except Exception as exc:
            log.critical(
                "policy_cache: unexpected error during signature verification: %s", exc
            )
            return False

    def _is_stale(self, bundle: PolicyBundle) -> bool:
        """Return True if *bundle* is older than allowed.

        Checks ``expires_at`` first (if set), then falls back to
        ``MAX_BUNDLE_AGE_DAYS`` from ``issued_at``.
        """
        now = datetime.now(tz=timezone.utc)

        if bundle.expires_at:
            try:
                expires_dt = self._parse_utc(bundle.expires_at)
                return now >= expires_dt
            except Exception as exc:
                log.warning(
                    "policy_cache: failed to parse expires_at=%r: %s — "
                    "falling back to MAX_BUNDLE_AGE_DAYS check.",
                    bundle.expires_at,
                    exc,
                )

        try:
            issued_dt = self._parse_utc(bundle.issued_at)
            age_days = (now - issued_dt).total_seconds() / 86400.0
            return age_days > self.MAX_BUNDLE_AGE_DAYS
        except Exception as exc:
            log.warning(
                "policy_cache: failed to parse issued_at=%r: %s — "
                "treating bundle as stale to be safe.",
                bundle.issued_at,
                exc,
            )
            return True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> BundleLoadResult:
        """Read and validate the bundle from ``_BUNDLE_PATH``.

        Called once in ``_proxy_lifespan`` at startup, and again after
        ``pull()`` refreshes the file on disk.

        Returns
        -------
        BundleLoadResult
            NONE — file absent.
            BUNDLE — valid, non-stale bundle.
            PARTIAL — stale + non-waivable; bundle kept for enforcement.
            INVALID — signature failed; bundle discarded.
        """
        if not self._BUNDLE_PATH.exists():
            log.info("policy_cache: no bundle on disk at %s", self._BUNDLE_PATH)
            self._bundle = None
            self._partial = False
            return BundleLoadResult.NONE

        try:
            raw = self._BUNDLE_PATH.read_text(encoding="utf-8")
            bundle_dict: dict = json.loads(raw)
        except Exception as exc:
            log.warning(
                "policy_cache: failed to read/parse bundle at %s: %s — treating as NONE.",
                self._BUNDLE_PATH,
                exc,
            )
            self._bundle = None
            self._partial = False
            return BundleLoadResult.NONE

        # Signature verification.
        if not self._verify_signature(bundle_dict):
            self._bundle = None
            self._partial = False
            return BundleLoadResult.INVALID

        # Construct dataclass (tolerate missing optional fields with defaults).
        try:
            bundle = PolicyBundle(
                version=bundle_dict.get("version", ""),
                issued_at=bundle_dict.get("issued_at", ""),
                expires_at=bundle_dict.get("expires_at"),
                waivable=bundle_dict.get("waivable", True),
                tc_rules=bundle_dict.get("tc_rules", []),
                lu_rules=bundle_dict.get("lu_rules", []),
                issued_by=bundle_dict.get("issued_by", ""),
                signature=bundle_dict.get("signature", ""),
            )
        except Exception as exc:
            log.warning(
                "policy_cache: failed to construct PolicyBundle from bundle dict: %s — "
                "treating as NONE.",
                exc,
            )
            self._bundle = None
            self._partial = False
            return BundleLoadResult.NONE

        # Staleness check.
        if self._is_stale(bundle):
            if bundle.waivable:
                log.warning(
                    "policy_cache: bundle version=%s is stale and waivable — discarding.",
                    bundle.version,
                )
                self._bundle = None
                self._partial = False
                return BundleLoadResult.NONE
            else:
                log.warning(
                    "policy_cache: bundle version=%s is stale but non-waivable — "
                    "enforcing in PartialBundle mode.",
                    bundle.version,
                )
                self._bundle = bundle
                self._partial = True
                return BundleLoadResult.PARTIAL

        log.info(
            "policy_cache: loaded bundle version=%s issued_at=%s",
            bundle.version,
            bundle.issued_at,
        )
        self._bundle = bundle
        self._partial = False
        return BundleLoadResult.BUNDLE

    def pull(self, base_url: str, token: str, verify_ssl: bool | str = True) -> dict:
        """Fetch the policy bundle from the control plane and reload.

        Uses ``urllib.request`` — no external dependencies.

        GET {base_url}/api/v1/policies/bundle

        Returns a status dict:
        - ``{"status": "ok", "version": "..."}`` on success.
        - ``{"status": "no_bundle"}`` on 404.
        - ``{"status": "error", "detail": "..."}`` on any other failure.
        """
        url = base_url.rstrip("/") + "/api/v1/policies/bundle"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}"},
            method="GET",
        )

        # urllib does not support a connect timeout distinct from read timeout;
        # the single ``timeout`` kwarg applies to both.
        ctx = _urllib_ssl_context(verify_ssl)

        try:
            # S3-B SSRF triage 2026-04-24: base_url is operator env KSWITCH_URL
            # (see proxy.py) — control-plane endpoint, not runtime input.
            # url = f"{base_url}/api/v1/policies/bundle" is a fixed path.
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:  # nosemgrep: dynamic-urllib-use-detected
                body = resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                log.info(
                    "policy_cache: no policy bundle available from control plane (404)"
                )
                return {"status": "no_bundle"}
            log.warning(
                "policy_cache: HTTP error fetching bundle from %s: %s", url, exc
            )
            return {"status": "error", "detail": str(exc)}
        except Exception as exc:
            log.warning(
                "policy_cache: network error fetching bundle from %s: %s", url, exc
            )
            return {"status": "error", "detail": str(exc)}

        # Validate JSON in memory BEFORE touching the on-disk bundle.
        # A misconfigured reverse proxy or WAF can return a 200 with an HTML
        # error page — writing that to disk would corrupt the last known-good
        # bundle and leave the proxy with no L2b rules until the next pull.
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            log.warning(
                "policy_cache: bundle response from %s is not valid JSON: %s",
                url,
                exc,
            )
            return {"status": "error", "detail": f"invalid JSON in bundle response: {exc}"}
        if not isinstance(parsed, dict):
            log.warning(
                "policy_cache: bundle response from %s is not a JSON object (got %s)",
                url,
                type(parsed).__name__,
            )
            return {"status": "error", "detail": "bundle response is not a JSON object"}

        # Write to disk only after confirming the payload is a valid JSON object.
        try:
            self._BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
            self._BUNDLE_PATH.write_bytes(body)
        except Exception as exc:
            log.warning(
                "policy_cache: failed to write bundle to %s: %s", self._BUNDLE_PATH, exc
            )
            return {"status": "error", "detail": str(exc)}

        # Reload from disk.
        result = self.load()
        if result in (BundleLoadResult.BUNDLE, BundleLoadResult.PARTIAL):
            version = self._bundle.version if self._bundle else "unknown"
            return {"status": "ok", "version": version}

        log.warning(
            "policy_cache: bundle written to disk but load() returned %s", result.value
        )
        return {"status": "error", "detail": f"load() returned {result.value} after pull"}

    def check(
        self,
        mcp_server_id: str,
        tool_name: str,
        agent_id: str,
    ) -> LocalAccessDecision:
        """Evaluate L2b LU rules from the loaded bundle.

        If no bundle is present, returns allow with reason ``"no_bundle"``.
        Most-restrictive wins: the first matching BLOCK rule short-circuits.

        Note: ``tc_rules`` are NOT evaluated here — they exist in the bundle
        for display/reference only. TC evaluation is performed server-side by
        the control plane.

        Parameters
        ----------
        mcp_server_id:
            The MCP server identifier for the call being checked.
        tool_name:
            The tool name being invoked.
        agent_id:
            The agent performing the call (reserved for future rule matching).

        Returns
        -------
        LocalAccessDecision

        Pattern matching semantics
        --------------------------
        ``mcp_server_id_pattern`` and ``tool_name_pattern`` are evaluated with
        ``re.search()``, which matches **anywhere** in the subject string (i.e.
        substring match, not full-string match).  Operators must use ``^...$``
        anchors when exact-match behaviour is required.

        Example — block only the server named "prod-db" exactly::

            {"mcp_server_id_pattern": "^prod-db$", "effect": "BLOCK", ...}

        Without anchors, ``"prod"`` would also block ``"my-dev-prod-mirror"``.
        This convention must be documented in the LU-rule authoring guide and
        validated by the admin API when LU rules are created.
        """
        if self._bundle is None:
            return LocalAccessDecision(allowed=True, reason="no_bundle")

        for rule in self._bundle.lu_rules:
            mcp_pattern: str | None = rule.get("mcp_server_id_pattern")
            tool_pattern: str | None = rule.get("tool_name_pattern")
            effect: str = rule.get("effect", "ALLOW").upper()
            reason: str = rule.get("reason", "")

            # A missing pattern means "match all".
            # Patterns use re.search() — see "Pattern matching semantics" above.
            mcp_matches = (
                mcp_pattern is None
                or bool(re.search(mcp_pattern, mcp_server_id, re.IGNORECASE))
            )
            tool_matches = (
                tool_pattern is None
                or bool(re.search(tool_pattern, tool_name, re.IGNORECASE))
            )

            if mcp_matches and tool_matches and effect == "BLOCK":
                log.warning(
                    "policy_cache [L2b]: rule %s blocked mcp_server_id=%r tool_name=%r agent_id=%r reason=%r",
                    rule.get("id", "?"),
                    mcp_server_id,
                    tool_name,
                    agent_id,
                    reason,
                )
                return LocalAccessDecision(
                    allowed=False,
                    reason=reason,
                    rule_id=rule.get("id"),
                )

        return LocalAccessDecision(allowed=True, reason="l2b_pass")

    @property
    def is_online(self) -> bool:
        """Delegate to ``ReachabilityCache.instance().is_online``."""
        return ReachabilityCache.instance().is_online


# ---------------------------------------------------------------------------
# ReachabilityCache class
# ---------------------------------------------------------------------------


class ReachabilityCache:
    """Singleton that tracks whether the KSwitch control plane is reachable.

    A HEAD probe to ``/api/v1/health/live`` is issued at most once every
    ``_ttl`` seconds (default 30 s) to avoid hammering the control plane.
    The blocking urllib call is offloaded to an executor so that the async
    proxy pipeline is not stalled.
    """

    _instance: ClassVar[ReachabilityCache | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self) -> None:
        self._is_online: bool = False
        self._last_check: float = 0.0
        self._ttl: float = 30.0

    @classmethod
    def instance(cls) -> ReachabilityCache:
        """Return the process-wide singleton, creating it on first call."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _probe(self, base_url: str, token: str, verify_ssl: bool | str = True) -> bool:
        """Blocking HEAD probe to ``{base_url}/api/v1/health/live``.

        Returns True on 2xx, False on any other response or error.
        """
        url = base_url.rstrip("/") + "/api/v1/health/live"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}"},
            method="HEAD",
        )

        ctx = _urllib_ssl_context(verify_ssl)

        try:
            # S3-B SSRF triage 2026-04-24: base_url is operator env KSWITCH_URL
            # (see proxy.py). url = f"{base_url}/api/v1/health/live"
            # is a fixed path — operator-config control plane.
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:  # nosemgrep: dynamic-urllib-use-detected
                online = 200 <= resp.status < 300
        except Exception as exc:
            log.debug("policy_cache [reachability]: probe failed: %s", exc)
            online = False

        self._is_online = online
        self._last_check = time.monotonic()
        log.debug("policy_cache [reachability]: is_online=%s", online)
        return online

    async def tick(self, base_url: str, token: str, verify_ssl: bool | str = True) -> bool:
        """Probe the health endpoint if the TTL has expired.

        Returns the current ``is_online`` value.  The blocking urllib call is
        dispatched to the default executor so the async event loop is not
        blocked.
        """
        if time.monotonic() - self._last_check >= self._ttl:
            # get_running_loop() is the correct call inside a coroutine — it
            # returns the loop that is already executing this coroutine.
            # get_event_loop() is deprecated in Python 3.10+ and raises a
            # DeprecationWarning when called without a running loop.
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._probe, base_url, token, verify_ssl)
        return self._is_online

    @property
    def is_online(self) -> bool:
        """Most-recently-known reachability state (no probe triggered)."""
        return self._is_online
