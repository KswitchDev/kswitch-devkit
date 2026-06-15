"""
Local bundle cache — disk-backed signed policy bundle for SDK-local evaluation.

Bundle file: ~/.kswitch/bundle/current.bundle  (JSON)
Manifest:    ~/.kswitch/bundle/manifest.json   (version, compiled_at, signature)

Bundle JSON schema (matches server PolicyBundle serialization):
{
  "version": 5,
  "bundle_id": "bundle:v5",
  "compiled_at": "2026-03-28T21:00:00Z",
  "cedar_text_enforce": "permit(...);",
  "cedar_text_shadow": "",
  "enforce_count": 3,
  "shadow_count": 0,
  "tool_count": 2,
  "tool_index": {"initiate_payment": {"requires_human_approval": false}},
  "signature": "sha256:<hex>"
}
"""
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

_DEFAULT_BUNDLE_DIR = os.path.expanduser("~/.kswitch/bundle")
_BUNDLE_FILE = "current.bundle"
_MANIFEST_FILE = "manifest.json"

# Max ages in seconds (mirrors server BUNDLE_MAX_AGE)
_BUNDLE_MAX_AGE = {
    "critical": 60,
    "high": 300,
    "medium": 900,
    "low": 3600,
}


class BundleNotAvailableError(Exception):
    """Raised when no valid local bundle is available."""


@dataclass
class LocalBundle:
    version: int
    bundle_id: str
    compiled_at: str
    cedar_text_enforce: str
    cedar_text_shadow: str
    enforce_count: int
    shadow_count: int
    tool_count: int
    tool_index: dict = field(default_factory=dict)
    signature: str = ""
    _loaded_at: float = field(default_factory=time.time, repr=False)

    def is_stale(self, risk_tier: str = "medium") -> bool:
        max_age = _BUNDLE_MAX_AGE.get(risk_tier.lower(), 900)
        return (time.time() - self._loaded_at) > max_age

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self.tool_index

    def requires_human_approval(self, tool_name: str) -> bool:
        meta = self.tool_index.get(tool_name, {})
        return meta.get("requires_human_approval", False)


class LocalBundleCache:
    """Disk-backed bundle cache with signature verification."""

    def __init__(self, bundle_dir: str = _DEFAULT_BUNDLE_DIR):
        self._dir = bundle_dir
        self._bundle: Optional[LocalBundle] = None

    @property
    def _bundle_path(self) -> str:
        return os.path.join(self._dir, _BUNDLE_FILE)

    def load(self) -> LocalBundle:
        """Load bundle from disk. Raises BundleNotAvailableError if missing/invalid."""
        if not os.path.exists(self._bundle_path):
            raise BundleNotAvailableError(
                f"No local bundle at {self._bundle_path}. "
                "Fetch from server: client.bundle.fetch_and_store()"
            )
        try:
            with open(self._bundle_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            raise BundleNotAvailableError(f"Bundle file unreadable: {e}")

        if not self._verify_signature(data):
            raise BundleNotAvailableError(
                "Bundle signature verification failed. "
                "Bundle may be tampered with or signing key rotated."
            )

        bundle = LocalBundle(
            version=data.get("version", 0),
            bundle_id=data.get("bundle_id", ""),
            compiled_at=data.get("compiled_at", ""),
            cedar_text_enforce=data.get("cedar_text_enforce", ""),
            cedar_text_shadow=data.get("cedar_text_shadow", ""),
            enforce_count=data.get("enforce_count", 0),
            shadow_count=data.get("shadow_count", 0),
            tool_count=data.get("tool_count", 0),
            tool_index=data.get("tool_index") or {},
            signature=data.get("signature", ""),
        )
        self._bundle = bundle
        return bundle

    def get_or_load(self) -> Optional[LocalBundle]:
        """Return cached bundle or load from disk. Returns None if unavailable."""
        if self._bundle is not None:
            return self._bundle
        try:
            return self.load()
        except BundleNotAvailableError:
            return None

    def invalidate(self) -> None:
        """Invalidate in-memory cache. Next call will reload from disk."""
        self._bundle = None

    def store(self, bundle_data: dict) -> None:
        """Write bundle JSON to disk. Called after fetching from server."""
        os.makedirs(self._dir, exist_ok=True)
        bundle_path = self._bundle_path
        tmp = bundle_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(bundle_data, f, indent=2)
        os.replace(tmp, bundle_path)  # Atomic write
        self._bundle = None  # Force reload

    def get_version(self) -> Optional[int]:
        bundle = self.get_or_load()
        return bundle.version if bundle else None

    @staticmethod
    def _verify_signature(data: dict) -> bool:
        """Verify bundle integrity using sha256 of content fields."""
        stored_sig = data.get("signature", "")
        if not stored_sig:
            # No signature — accept in dev mode (KSWITCH_ENV != production)
            if os.environ.get("KSWITCH_ENV", "development") == "production":
                return False
            return True
        # Compute signature over stable fields
        content = json.dumps({
            k: v for k, v in data.items()
            if k not in ("signature", "_loaded_at")
        }, sort_keys=True)
        expected = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
        return stored_sig == expected


# Module-level singleton
_cache = LocalBundleCache()


def load_current_bundle() -> Optional[LocalBundle]:
    """Load the current local bundle. Returns None if unavailable."""
    return _cache.get_or_load()


def get_bundle_cache() -> LocalBundleCache:
    return _cache
