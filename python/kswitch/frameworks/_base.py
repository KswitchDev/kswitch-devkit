"""Base classes and action mapping for KSwitch framework adapters.

All framework adapters share the same integration pattern:
  1. Accept a KSwitchRuntime (or client + agent_id + mcp_server_id)
  2. Translate framework-native tool invocations to runtime.invoke(tool_name, **kwargs)
  3. Return the result (output policy applied inside runtime.invoke)

Performance requirement: adapter overhead ≤ 5ms p99 (not counting enforcement latency).
The enforce() call itself adds ~1-3ms via local PDP (in-process Cedar). The wrapper
overhead is a single function call + type conversion — well within the 5ms budget.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..invoke import KSwitchRuntime


class KSwitchFrameworkAdapter:
    """Base adapter. Subclasses translate framework interfaces to runtime.invoke()."""

    def __init__(
        self,
        name: str,
        func: Callable[..., Any],
        runtime: "KSwitchRuntime",
        description: str = "",
    ) -> None:
        self._name = name
        self._func = func
        self._runtime = runtime
        self._description = description
        # Register the raw function with the runtime so invoke() can find it
        self._runtime.register(name, func)

    def enforce(self, **kwargs: Any) -> Any:
        """Route to governance pipeline. All enforcement, output policy, and audit apply."""
        return self._runtime.invoke(self._name, **kwargs)

    async def enforce_async(self, **kwargs: Any) -> Any:
        """Async version of enforce(). Routes to async runtime if available."""
        runtime = self._runtime
        # If runtime has invoke_async, use it; otherwise fall back to sync
        if hasattr(runtime, "invoke_async"):
            return await runtime.invoke_async(self._name, **kwargs)  # type: ignore[union-attr]
        return runtime.invoke(self._name, **kwargs)
