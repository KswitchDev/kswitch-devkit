"""
Local context cache — disk-backed agent/MCP context for SDK-local evaluation.

Context pack file: ~/.kswitch/context/{sanitized_agent_id}.contextpack  (JSON)

Context pack JSON schema (subset of server ContextPack):
{
  "agent_id": "agent:fraud-detector@bank.internal",
  "status": "active",
  "risk_tier": "high",
  "data_classifications": ["PII"],
  "is_revoked": false,
  "compiled_at": "2026-03-28T21:00:00Z",
  "pack_version": 3
}
"""
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

_DEFAULT_CONTEXT_DIR = os.path.expanduser("~/.kswitch/context")

# Context pack TTLs in seconds (mirrors server CONTEXT_PACK_TTL)
_CONTEXT_PACK_TTL = {
    "critical": 5,
    "high": 30,
    "medium": 120,
    "low": 300,
}


class ContextNotAvailableError(Exception):
    """Raised when no valid context pack is available for an agent."""


@dataclass
class LocalContextPack:
    agent_id: str
    status: str = "unknown"
    risk_tier: str = "medium"
    data_classifications: list = field(default_factory=list)
    is_revoked: bool = False
    compiled_at: str = ""
    pack_version: int = 0
    _loaded_at: float = field(default_factory=time.time, repr=False)

    def is_active(self) -> bool:
        return self.status in ("active", "declared", "pending") and not self.is_revoked

    def is_stale(self) -> bool:
        ttl = _CONTEXT_PACK_TTL.get(self.risk_tier.lower(), 120)
        return (time.time() - self._loaded_at) > ttl


def _sanitize_agent_id(agent_id: str) -> str:
    """Convert agent ID to safe filename."""
    return agent_id.replace(":", "_").replace("/", "_").replace("@", "_at_").replace(".", "_")


class LocalContextCache:
    """Disk-backed context pack cache."""

    def __init__(self, context_dir: str = _DEFAULT_CONTEXT_DIR):
        self._dir = context_dir
        self._packs: dict[str, LocalContextPack] = {}

    def _path(self, agent_id: str) -> str:
        return os.path.join(self._dir, f"{_sanitize_agent_id(agent_id)}.contextpack")

    def load(self, agent_id: str) -> LocalContextPack:
        """Load context pack for agent from disk."""
        path = self._path(agent_id)
        if not os.path.exists(path):
            raise ContextNotAvailableError(
                f"No local context pack for {agent_id} at {path}. "
                "Fetch from server: client.context.fetch_and_store(agent_id)"
            )
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            raise ContextNotAvailableError(f"Context pack unreadable for {agent_id}: {e}")

        pack = LocalContextPack(
            agent_id=data.get("agent_id", agent_id),
            status=data.get("status", "unknown"),
            risk_tier=data.get("risk_tier", "medium"),
            data_classifications=data.get("data_classifications") or [],
            is_revoked=data.get("is_revoked", False),
            compiled_at=data.get("compiled_at", ""),
            pack_version=data.get("pack_version", 0),
        )
        self._packs[agent_id] = pack
        return pack

    def get_or_load(self, agent_id: str) -> Optional[LocalContextPack]:
        """Return cached pack or load from disk. Returns None if unavailable."""
        cached = self._packs.get(agent_id)
        if cached is not None and not cached.is_stale():
            return cached
        try:
            return self.load(agent_id)
        except ContextNotAvailableError:
            return None

    def store(self, agent_id: str, pack_data: dict) -> None:
        """Write context pack JSON to disk. Called after fetching from server."""
        os.makedirs(self._dir, exist_ok=True)
        path = self._path(agent_id)
        tmp = path + ".tmp"
        pack_data["agent_id"] = agent_id
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(pack_data, f, indent=2)
        os.replace(tmp, path)
        self._packs.pop(agent_id, None)  # Force reload

    def invalidate(self, agent_id: str | None = None, *, remove_disk: bool = False) -> None:
        """Invalidate one context pack or all in-memory packs.

        When ``remove_disk`` is true, also remove persisted context pack files.
        This is used by authenticated server invalidation events so stale disk
        packs cannot be reloaded after a lifecycle mutation.
        """
        if agent_id is None:
            self._packs.clear()
            if remove_disk and os.path.isdir(self._dir):
                for name in os.listdir(self._dir):
                    if name.endswith(".contextpack"):
                        try:
                            os.remove(os.path.join(self._dir, name))
                        except OSError:
                            pass
            return

        self._packs.pop(agent_id, None)
        if remove_disk:
            try:
                os.remove(self._path(agent_id))
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def get_version(self, agent_id: str) -> Optional[int]:
        pack = self.get_or_load(agent_id)
        return pack.pack_version if pack else None


# Module-level singleton
_cache = LocalContextCache()


def load_context_pack(agent_id: str) -> Optional[LocalContextPack]:
    return _cache.get_or_load(agent_id)


def get_context_cache() -> LocalContextCache:
    return _cache
