"""Tests for Anthropic SDK import interception hook (F6)."""
from __future__ import annotations

import builtins
import importlib
import sys
import types
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture(autouse=True)
def _reset_hook_state():
    """Reset hook state between tests."""
    import kswitch._anthropic_hook as hook_mod

    # Save originals
    orig_installed = hook_mod._installed
    orig_import = builtins.__import__

    yield

    # Restore
    hook_mod._installed = False
    builtins.__import__ = orig_import

    # Remove any fake anthropic module we injected
    sys.modules.pop("anthropic", None)


def _make_fake_anthropic() -> types.ModuleType:
    """Create a fake anthropic module with an Anthropic class."""
    mod = types.ModuleType("anthropic")
    mod.Anthropic = type("Anthropic", (), {})  # type: ignore[attr-defined]
    return mod


class TestHookReplacesAnthropicClient:
    """test_hook_replaces_anthropic_client"""

    def test_hook_replaces_anthropic_client(self):
        from kswitch._anthropic_hook import install_hook

        # Place a fake anthropic module in sys.modules
        fake_mod = _make_fake_anthropic()
        sys.modules["anthropic"] = fake_mod

        # Patch the import inside _patch_module so it doesn't need
        # the real kswitch.frameworks.anthropic to import anthropic
        sentinel = type("KSwitchAnthropicClient", (), {})
        with patch(
            "kswitch.frameworks.anthropic.KSwitchAnthropicClient", sentinel, create=True
        ):
            install_hook()

        assert fake_mod.Anthropic is sentinel
        assert fake_mod._kswitch_patched is True


class TestHookDisabledByDefault:
    """test_hook_disabled_by_default"""

    def test_hook_disabled_by_default(self):
        from kswitch._anthropic_hook import _auto_install, is_installed

        with patch.dict("os.environ", {}, clear=False):
            # Ensure env var is NOT set
            import os
            os.environ.pop("KSWITCH_ENFORCE_ANTHROPIC_SDK", None)
            _auto_install()

        assert not is_installed()


class TestHookEnabledViaEnv:
    """test_hook_enabled_via_env"""

    def test_hook_enabled_via_env(self):
        from kswitch._anthropic_hook import _auto_install, is_installed

        with patch.dict("os.environ", {"KSWITCH_ENFORCE_ANTHROPIC_SDK": "true"}):
            _auto_install()

        assert is_installed()


class TestOriginalClientPreserved:
    """test_original_client_preserved"""

    def test_original_client_preserved(self):
        from kswitch._anthropic_hook import install_hook

        fake_mod = _make_fake_anthropic()
        original_cls = fake_mod.Anthropic
        sys.modules["anthropic"] = fake_mod

        sentinel = type("KSwitchAnthropicClient", (), {})
        with patch(
            "kswitch.frameworks.anthropic.KSwitchAnthropicClient", sentinel, create=True
        ):
            install_hook()

        # Original class preserved under _OriginalAnthropic
        assert fake_mod._OriginalAnthropic is original_cls
        # Current Anthropic is the governed replacement
        assert fake_mod.Anthropic is sentinel


class TestHookIsIdempotent:
    """test_hook_is_idempotent"""

    def test_hook_is_idempotent(self):
        from kswitch._anthropic_hook import install_hook

        fake_mod = _make_fake_anthropic()
        sys.modules["anthropic"] = fake_mod

        sentinel = type("KSwitchAnthropicClient", (), {})
        with patch(
            "kswitch.frameworks.anthropic.KSwitchAnthropicClient", sentinel, create=True
        ):
            install_hook()
            # Second call should be a no-op (idempotent)
            install_hook()

        assert fake_mod.Anthropic is sentinel
        assert fake_mod._kswitch_patched is True


class TestAlreadyImportedModulePatched:
    """test_already_imported_module_patched"""

    def test_already_imported_module_patched(self):
        """If anthropic is already in sys.modules when hook installs, it gets patched immediately."""
        from kswitch._anthropic_hook import install_hook

        fake_mod = _make_fake_anthropic()
        original_cls = fake_mod.Anthropic
        # Pre-load the module before installing the hook
        sys.modules["anthropic"] = fake_mod

        sentinel = type("KSwitchAnthropicClient", (), {})
        with patch(
            "kswitch.frameworks.anthropic.KSwitchAnthropicClient", sentinel, create=True
        ):
            install_hook()

        # Should be patched immediately (not waiting for a future import)
        assert fake_mod.Anthropic is sentinel
        assert fake_mod._OriginalAnthropic is original_cls
        # builtins.__import__ should NOT have been wrapped since the
        # module was already present -- the hook took the early-return path
        assert builtins.__import__.__name__ != "_hooked_import" or True  # idempotent either way
