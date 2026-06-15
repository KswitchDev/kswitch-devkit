"""
Anthropic SDK import interception hook (F6 — EP-006).

When enabled via KSWITCH_ENFORCE_ANTHROPIC_SDK=true, intercepts
``import anthropic`` and replaces ``anthropic.Anthropic`` with
``KSwitchAnthropicClient``. Transparent to agent code.

Usage:
    # Automatic (env var):
    KSWITCH_ENFORCE_ANTHROPIC_SDK=true python my_agent.py

    # Manual:
    from kswitch._anthropic_hook import install_hook
    install_hook()

    import anthropic
    client = anthropic.Anthropic()  # <- now a KSwitchAnthropicClient

Implementation:
    Uses sys.modules post-import patching (not sys.meta_path).
    After the real anthropic module loads, replaces its Anthropic class
    with a wrapper that returns KSwitchAnthropicClient.

    Why not sys.meta_path: sys.meta_path finders run before the real
    module loader and would prevent the real anthropic from loading.
    We want the real module to load (for types, exceptions, etc) but
    with its Anthropic class replaced.
"""
from __future__ import annotations

import builtins
import logging
import os
import sys

logger = logging.getLogger(__name__)

_installed = False


def install_hook() -> None:
    """Install the Anthropic SDK interception hook.

    After calling this, any ``import anthropic`` will have its
    ``Anthropic`` class replaced with ``KSwitchAnthropicClient``.

    Idempotent -- safe to call multiple times.
    """
    global _installed
    if _installed:
        return

    _installed = True

    # If anthropic is already imported, patch it now
    if "anthropic" in sys.modules:
        _patch_module(sys.modules["anthropic"])
        return

    # Otherwise, install a post-import hook by wrapping builtins.__import__
    # to detect when anthropic loads.
    _original_import = builtins.__import__

    def _hooked_import(name, *args, **kwargs):
        result = _original_import(name, *args, **kwargs)
        if name == "anthropic" and "anthropic" in sys.modules:
            _patch_module(sys.modules["anthropic"])
        return result

    builtins.__import__ = _hooked_import
    logger.info("KSwitch Anthropic SDK enforcement hook installed")


def _patch_module(mod) -> None:
    """Replace anthropic.Anthropic with KSwitchAnthropicClient."""
    if getattr(mod, "_kswitch_patched", False):
        return

    # Save original for reference
    mod._OriginalAnthropic = getattr(mod, "Anthropic", None)

    # Import the governed client
    from kswitch.frameworks.anthropic import KSwitchAnthropicClient

    # Replace
    mod.Anthropic = KSwitchAnthropicClient
    mod._kswitch_patched = True
    logger.info("anthropic.Anthropic replaced with KSwitchAnthropicClient")


def is_installed() -> bool:
    """Check if the hook is currently installed."""
    return _installed


def _auto_install() -> None:
    """Called at kswitch import time if env var is set."""
    if os.getenv("KSWITCH_ENFORCE_ANTHROPIC_SDK", "").lower() == "true":
        install_hook()
