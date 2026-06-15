"""Anthropic SDK adapter hook points for KSwitch governance.

The import hook in :mod:`kswitch._anthropic_hook` replaces
``anthropic.Anthropic`` with ``KSwitchAnthropicClient``. This class preserves the
upstream constructor and delegates attributes to the original client, giving the
SDK a stable interception point without making the optional ``anthropic``
package mandatory at KSwitch import time.
"""

from __future__ import annotations

import sys
from typing import Any


class KSwitchAnthropicClient:
    """Transparent proxy for the original Anthropic client.

    The import hook stores the original class as ``anthropic._OriginalAnthropic``
    before replacing ``anthropic.Anthropic``. This adapter instantiates that
    original client and delegates attribute access. Governance-specific method
    wrappers can be layered here without changing the import-hook contract.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        anthropic_mod = sys.modules.get("anthropic")
        original_cls = getattr(anthropic_mod, "_OriginalAnthropic", None)
        if original_cls is None:
            raise RuntimeError(
                "KSwitchAnthropicClient requires kswitch._anthropic_hook to preserve "
                "anthropic._OriginalAnthropic before patching."
            )
        self._client = original_cls(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
