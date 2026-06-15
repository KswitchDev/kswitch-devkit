"""KSwitch adapter for LangChain tools.

Wraps any Python callable as a LangChain BaseTool with full KSwitch governance.
All LangChain tool calls route through KSwitchRuntime.invoke() — Cedar evaluation,
obligation blocking, output policy, and audit all apply unchanged.

Requires: pip install kswitch-sdk[langchain]

Usage:
    from kswitch.frameworks.langchain import KSwitchLangChainTool

    tool = KSwitchLangChainTool(
        name="query_database",
        description="Query customer records",
        func=db.query,
        runtime=kswitch_runtime,
    )

    # Use with any LangChain agent
    agent = initialize_agent(tools=[tool], llm=llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
"""

from __future__ import annotations

from typing import Any, Callable, Optional, TYPE_CHECKING

try:
    from langchain.tools import BaseTool
    _LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    _LANGCHAIN_AVAILABLE = False
    BaseTool = object  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from ..invoke import KSwitchRuntime


class KSwitchLangChainTool(BaseTool):  # type: ignore[misc]
    """LangChain BaseTool that routes all invocations through KSwitch governance.

    Drop-in replacement for any LangChain tool. The LangChain agent calls
    _run() / _arun() normally — governance is transparently applied.
    """

    # Pydantic-compatible field declarations for LangChain v0.1+
    name: str = ""
    description: str = ""

    # Non-pydantic attributes (set in __init__)
    _ks_runtime: "KSwitchRuntime"
    _ks_func: Callable[..., Any]

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        runtime: "KSwitchRuntime",
        **kwargs: Any,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:
            raise ImportError(
                "langchain is not installed. Run: pip install kswitch-sdk[langchain]"
            )
        super().__init__(name=name, description=description, **kwargs)
        object.__setattr__(self, "_ks_func", func)
        object.__setattr__(self, "_ks_runtime", runtime)
        # Register with runtime so invoke() can find the raw callable
        runtime.register(name, func)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Sync tool invocation — routes through KSwitch governance."""
        # LangChain may pass a single string arg for simple tools
        if args and not kwargs:
            kwargs = {"input": args[0]} if len(args) == 1 else {"args": args}
        return self._ks_runtime.invoke(self.name, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Async tool invocation — routes through KSwitch governance."""
        if args and not kwargs:
            kwargs = {"input": args[0]} if len(args) == 1 else {"args": args}
        runtime = self._ks_runtime
        if hasattr(runtime, "invoke_async"):
            return await runtime.invoke_async(self.name, **kwargs)  # type: ignore[union-attr]
        return runtime.invoke(self.name, **kwargs)
