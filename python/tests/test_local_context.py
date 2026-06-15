"""Tests for LocalContextCache — disk-backed context pack loading and TTL."""
import json
import os
import time

import pytest

from kswitch.context.local_cache import (
    ContextNotAvailableError,
    LocalContextCache,
    LocalContextPack,
    _sanitize_agent_id,
)


def _make_context_data(
    agent_id="agent:fraud-detector@bank.internal",
    status="active",
    risk_tier="high",
    data_classifications=None,
    is_revoked=False,
    pack_version=3,
):
    return {
        "agent_id": agent_id,
        "status": status,
        "risk_tier": risk_tier,
        "data_classifications": data_classifications or ["PII"],
        "is_revoked": is_revoked,
        "compiled_at": "2026-03-28T21:00:00Z",
        "pack_version": pack_version,
    }


def _write_context(tmp_dir, agent_id, data):
    safe = _sanitize_agent_id(agent_id)
    path = os.path.join(tmp_dir, f"{safe}.contextpack")
    with open(path, "w") as f:
        json.dump(data, f)
    return path


AGENT_ID = "agent:fraud-detector@bank.internal"


class TestLocalContextCacheLoad:
    def test_load_valid_context(self, tmp_path):
        data = _make_context_data()
        _write_context(str(tmp_path), AGENT_ID, data)
        cache = LocalContextCache(context_dir=str(tmp_path))
        pack = cache.load(AGENT_ID)
        assert pack.agent_id == AGENT_ID
        assert pack.status == "active"
        assert pack.risk_tier == "high"
        assert "PII" in pack.data_classifications

    def test_load_missing_raises(self, tmp_path):
        cache = LocalContextCache(context_dir=str(tmp_path))
        with pytest.raises(ContextNotAvailableError, match="No local context pack"):
            cache.load(AGENT_ID)

    def test_load_corrupt_json_raises(self, tmp_path):
        safe = _sanitize_agent_id(AGENT_ID)
        path = os.path.join(str(tmp_path), f"{safe}.contextpack")
        with open(path, "w") as f:
            f.write("BAD{{{")
        cache = LocalContextCache(context_dir=str(tmp_path))
        with pytest.raises(ContextNotAvailableError, match="unreadable"):
            cache.load(AGENT_ID)


class TestLocalContextCacheGetOrLoad:
    def test_get_or_load_returns_none_when_missing(self, tmp_path):
        cache = LocalContextCache(context_dir=str(tmp_path))
        assert cache.get_or_load(AGENT_ID) is None

    def test_get_or_load_caches_in_memory(self, tmp_path):
        data = _make_context_data()
        _write_context(str(tmp_path), AGENT_ID, data)
        cache = LocalContextCache(context_dir=str(tmp_path))
        p1 = cache.get_or_load(AGENT_ID)
        p2 = cache.get_or_load(AGENT_ID)
        assert p1 is p2

    def test_invalidate_clears_cache(self, tmp_path):
        data = _make_context_data()
        _write_context(str(tmp_path), AGENT_ID, data)
        cache = LocalContextCache(context_dir=str(tmp_path))
        p1 = cache.get_or_load(AGENT_ID)
        cache.invalidate(AGENT_ID)
        p2 = cache.get_or_load(AGENT_ID)
        assert p1 is not p2

    def test_invalidate_forces_disk_reload(self, tmp_path):
        _write_context(str(tmp_path), AGENT_ID, _make_context_data(pack_version=1))
        cache = LocalContextCache(context_dir=str(tmp_path))
        p1 = cache.get_or_load(AGENT_ID)
        assert p1.pack_version == 1

        _write_context(str(tmp_path), AGENT_ID, _make_context_data(pack_version=2))
        assert cache.get_or_load(AGENT_ID).pack_version == 1

        cache.invalidate(AGENT_ID)
        assert cache.get_or_load(AGENT_ID).pack_version == 2


class TestLocalContextPackStatus:
    def test_active_agent_is_active(self):
        pack = LocalContextPack(agent_id=AGENT_ID, status="active")
        assert pack.is_active()

    def test_declared_agent_is_active(self):
        pack = LocalContextPack(agent_id=AGENT_ID, status="declared")
        assert pack.is_active()

    def test_pending_agent_is_active(self):
        pack = LocalContextPack(agent_id=AGENT_ID, status="pending")
        assert pack.is_active()

    def test_suspended_agent_not_active(self):
        pack = LocalContextPack(agent_id=AGENT_ID, status="suspended")
        assert not pack.is_active()

    def test_revoked_agent_not_active(self):
        pack = LocalContextPack(agent_id=AGENT_ID, status="active", is_revoked=True)
        assert not pack.is_active()


class TestLocalContextPackStale:
    def test_fresh_pack_not_stale(self):
        pack = LocalContextPack(agent_id=AGENT_ID, risk_tier="high")
        assert not pack.is_stale()

    def test_old_high_pack_is_stale(self):
        pack = LocalContextPack(agent_id=AGENT_ID, risk_tier="high")
        pack._loaded_at = time.time() - 31  # TTL for high = 30s
        assert pack.is_stale()

    def test_old_critical_pack_is_stale(self):
        pack = LocalContextPack(agent_id=AGENT_ID, risk_tier="critical")
        pack._loaded_at = time.time() - 6  # TTL for critical = 5s
        assert pack.is_stale()

    def test_old_low_pack_not_stale_within_ttl(self):
        pack = LocalContextPack(agent_id=AGENT_ID, risk_tier="low")
        pack._loaded_at = time.time() - 100  # TTL for low = 300s
        assert not pack.is_stale()


class TestLocalContextCacheStore:
    def test_store_creates_file(self, tmp_path):
        cache = LocalContextCache(context_dir=str(tmp_path))
        data = _make_context_data()
        cache.store(AGENT_ID, data)
        safe = _sanitize_agent_id(AGENT_ID)
        assert os.path.exists(os.path.join(str(tmp_path), f"{safe}.contextpack"))

    def test_store_sets_agent_id_field(self, tmp_path):
        cache = LocalContextCache(context_dir=str(tmp_path))
        data = _make_context_data()
        cache.store(AGENT_ID, data)
        pack = cache.load(AGENT_ID)
        assert pack.agent_id == AGENT_ID

    def test_store_invalidates_memory_cache(self, tmp_path):
        data = _make_context_data()
        _write_context(str(tmp_path), AGENT_ID, data)
        cache = LocalContextCache(context_dir=str(tmp_path))
        _ = cache.get_or_load(AGENT_ID)
        assert AGENT_ID in cache._packs
        cache.store(AGENT_ID, data)
        assert AGENT_ID not in cache._packs


class TestAgentIdSanitization:
    def test_sanitize_colon(self):
        assert ":" not in _sanitize_agent_id("agent:name@domain")

    def test_sanitize_at(self):
        assert "@" not in _sanitize_agent_id("agent:name@domain")

    def test_sanitize_dot(self):
        result = _sanitize_agent_id("agent:name@domain.internal")
        assert "." not in result

    def test_consistent(self):
        a = _sanitize_agent_id("agent:fraud@bank.internal")
        b = _sanitize_agent_id("agent:fraud@bank.internal")
        assert a == b
