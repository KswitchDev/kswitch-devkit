"""Tests for LocalBundleCache — disk-backed bundle loading and signature verification."""
import hashlib
import json
import os
import tempfile
import time

import pytest

from kswitch.bundle.local_cache import (
    BundleNotAvailableError,
    LocalBundle,
    LocalBundleCache,
)


def _make_bundle_data(
    version=5,
    enforce_count=2,
    shadow_count=0,
    tool_index=None,
    add_signature=True,
):
    data = {
        "version": version,
        "bundle_id": f"bundle:v{version}",
        "compiled_at": "2026-03-28T21:00:00Z",
        "cedar_text_enforce": 'permit(principal, action, resource);',
        "cedar_text_shadow": "",
        "enforce_count": enforce_count,
        "shadow_count": shadow_count,
        "tool_count": len(tool_index or {}),
        "tool_index": tool_index or {},
    }
    if add_signature:
        content = json.dumps(data, sort_keys=True)
        data["signature"] = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    return data


def _write_bundle(tmp_dir, data):
    bundle_path = os.path.join(tmp_dir, "current.bundle")
    with open(bundle_path, "w") as f:
        json.dump(data, f)
    return bundle_path


class TestLocalBundleCacheLoad:
    def test_load_valid_bundle(self, tmp_path):
        data = _make_bundle_data()
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        bundle = cache.load()
        assert bundle.version == 5
        assert bundle.bundle_id == "bundle:v5"
        assert bundle.enforce_count == 2

    def test_load_missing_file_raises(self, tmp_path):
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        with pytest.raises(BundleNotAvailableError, match="No local bundle"):
            cache.load()

    def test_load_corrupt_json_raises(self, tmp_path):
        bundle_path = os.path.join(str(tmp_path), "current.bundle")
        with open(bundle_path, "w") as f:
            f.write("NOT_JSON{{{")
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        with pytest.raises(BundleNotAvailableError, match="unreadable"):
            cache.load()

    def test_load_bad_signature_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KSWITCH_ENV", "production")
        data = _make_bundle_data()
        data["signature"] = "sha256:badhash"
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        with pytest.raises(BundleNotAvailableError, match="signature"):
            cache.load()

    def test_no_signature_allowed_in_dev(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KSWITCH_ENV", "development")
        data = _make_bundle_data(add_signature=False)
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        bundle = cache.load()
        assert bundle.version == 5

    def test_no_signature_denied_in_production(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KSWITCH_ENV", "production")
        data = _make_bundle_data(add_signature=False)
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        with pytest.raises(BundleNotAvailableError, match="signature"):
            cache.load()


class TestLocalBundleCacheGetOrLoad:
    def test_get_or_load_returns_none_when_missing(self, tmp_path):
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        assert cache.get_or_load() is None

    def test_get_or_load_caches_in_memory(self, tmp_path):
        data = _make_bundle_data()
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        b1 = cache.get_or_load()
        b2 = cache.get_or_load()
        assert b1 is b2  # Same object returned from cache

    def test_invalidate_clears_cache(self, tmp_path):
        data = _make_bundle_data()
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        b1 = cache.get_or_load()
        cache.invalidate()
        b2 = cache.get_or_load()
        assert b1 is not b2


class TestLocalBundleStaleDetection:
    def test_fresh_bundle_not_stale(self, tmp_path):
        data = _make_bundle_data()
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        bundle = cache.load()
        assert not bundle.is_stale("medium")

    def test_old_bundle_is_stale(self, tmp_path):
        data = _make_bundle_data()
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        bundle = cache.load()
        # Backdate the loaded_at to simulate staleness
        bundle._loaded_at = time.time() - 10000
        assert bundle.is_stale("medium")

    def test_critical_tier_stale_after_60s(self, tmp_path):
        data = _make_bundle_data()
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        bundle = cache.load()
        bundle._loaded_at = time.time() - 61
        assert bundle.is_stale("critical")
        # But NOT stale for low tier (3600s)
        assert not bundle.is_stale("low")


class TestLocalBundleToolIndex:
    def test_has_tool(self, tmp_path):
        tool_index = {"initiate_payment": {"requires_human_approval": False}}
        data = _make_bundle_data(tool_index=tool_index)
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        bundle = cache.load()
        assert bundle.has_tool("initiate_payment")
        assert not bundle.has_tool("unknown_tool")

    def test_requires_human_approval(self, tmp_path):
        tool_index = {
            "approve_transaction": {"requires_human_approval": True},
            "get_balance": {"requires_human_approval": False},
        }
        data = _make_bundle_data(tool_index=tool_index)
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        bundle = cache.load()
        assert bundle.requires_human_approval("approve_transaction")
        assert not bundle.requires_human_approval("get_balance")


class TestLocalBundleCacheStore:
    def test_store_creates_file(self, tmp_path):
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        data = _make_bundle_data()
        cache.store(data)
        assert os.path.exists(os.path.join(str(tmp_path), "current.bundle"))

    def test_store_invalidates_memory_cache(self, tmp_path):
        data = _make_bundle_data()
        _write_bundle(str(tmp_path), data)
        cache = LocalBundleCache(bundle_dir=str(tmp_path))
        _ = cache.get_or_load()
        assert cache._bundle is not None
        cache.store(data)
        assert cache._bundle is None
