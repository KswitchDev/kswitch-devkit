"""KSwitch adapter for Semantic Kernel plugins.

Wraps Python callables as a governed Semantic Kernel plugin. All SK function
calls route through KSwitchRuntime.invoke() with full governance.

Requires: pip install kswitch-sdk[semantic_kernel]

Usage:
    from kswitch.frameworks.semantic_kernel import KSwitchSKPlugin

    plugin = KSwitchSKPlugin(
        plugin_name="CustomerPlugin",
        runtime=kswitch_runtime,
        functions={
            "lookup_customer": (crm.lookup, "Lookup customer by ID"),
            "update_address": (crm.update_address, "Update customer address"),
        },
    )

    kernel = Kernel()
    kernel.add_plugin(plugin, plugin_name="CustomerPlugin")
"""

from __future__ import annotations

from typing import Any, Callable, TYPE_CHECKING

try:
    from semantic_kernel.functions import KernelFunction, kernel_function
    from semantic_kernel.plugin_definition import KernelPlugin
    _SK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SK_AVAILABLE = False
    KernelFunction = object  # type: ignore[assignment,misc]
    KernelPlugin = object  # type: ignore[assignment,misc]

    def kernel_function(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return func
        return decorator

if TYPE_CHECKING:
    from ..invoke import KSwitchRuntime


class KSwitchSKPlugin:
    """Semantic Kernel plugin where every function is governed by KSwitch.

    Creates a plugin object with one governed method per entry in `functions`.
    Each method is decorated with @kernel_function and routes to runtime.invoke().
    """

    def __init__(
        self,
        plugin_name: str,
        runtime: "KSwitchRuntime",
        functions: dict[str, tuple[Callable[..., Any], str]],
    ) -> None:
        """
        Args:
            plugin_name: Name of the Semantic Kernel plugin.
            runtime: KSwitchRuntime instance.
            functions: Dict of {function_name: (callable, description)}.
        """
        if not _SK_AVAILABLE:
            raise ImportError(
                "semantic-kernel is not installed. "
                "Run: pip install kswitch-sdk[semantic_kernel]"
            )
        self._plugin_name = plugin_name
        self._runtime = runtime

        for func_name, (func, description) in functions.items():
            # Register raw function with the runtime
            runtime.register(func_name, func)
            # Attach a governed method to this plugin instance
            self._attach_governed_function(func_name, description)

    def _attach_governed_function(self, func_name: str, description: str) -> None:
        """Dynamically attach a governed @kernel_function method for func_name."""
        runtime = self._runtime

        @kernel_function(name=func_name, description=description)
        def governed(**kwargs: Any) -> Any:
            return runtime.invoke(func_name, **kwargs)

        governed.__name__ = func_name
        setattr(self, func_name, governed)
