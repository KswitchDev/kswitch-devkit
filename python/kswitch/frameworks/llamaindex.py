"""KSwitch adapter for LlamaIndex tools.

Wraps Python callables as governed LlamaIndex BaseTool instances.
All LlamaIndex tool calls route through KSwitchRuntime.invoke() with full
Cedar evaluation, obligation blocking, output policy, and audit.

Requires: pip install kswitch-sdk[llamaindex]

Usage:
    from kswitch.frameworks.llamaindex import KSwitchLlamaIndexTool

    tool = KSwitchLlamaIndexTool(
        name="search_documents",
        description="Search internal document store",
        func=doc_store.search,
        runtime=kswitch_runtime,
    )

    # Use with any LlamaIndex agent
    agent = ReActAgent.from_tools(tools=[tool], llm=llm)
"""

from __future__ import annotations

from typing import Any, Callable, Optional, TYPE_CHECKING

try:
    from llama_index.core.tools import BaseTool, ToolMetadata, ToolOutput
    _LLAMA_AVAILABLE = True
except ImportError:
    try:
        from llama_index.tools import BaseTool, ToolMetadata, ToolOutput  # type: ignore[no-redef]
        _LLAMA_AVAILABLE = True
    except ImportError:  # pragma: no cover
        _LLAMA_AVAILABLE = False
        BaseTool = object  # type: ignore[assignment,misc]
        ToolMetadata = object  # type: ignore[assignment,misc]

        class ToolOutput:  # type: ignore[no-redef]
            def __init__(self, content: str, tool_name: str, raw_input: dict[str, Any], raw_output: Any) -> None:
                self.content = content

if TYPE_CHECKING:
    from ..invoke import KSwitchRuntime


class KSwitchLlamaIndexTool(BaseTool):  # type: ignore[misc]
    """LlamaIndex BaseTool with KSwitch governance.

    All calls (sync and async) route through KSwitchRuntime.invoke() so that
    Cedar policy evaluation, obligation blocking, output policy, and audit
    apply to every tool invocation made by the LlamaIndex agent.
    """

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        runtime: "KSwitchRuntime",
    ) -> None:
        if not _LLAMA_AVAILABLE:
            raise ImportError(
                "llama-index is not installed. Run: pip install kswitch-sdk[llamaindex]"
            )
        self._ks_name = name
        self._ks_description = description
        self._ks_func = func
        self._ks_runtime = runtime
        # Register with runtime
        runtime.register(name, func)

    @property
    def metadata(self) -> Any:
        return ToolMetadata(name=self._ks_name, description=self._ks_description)

    def __call__(self, input: Any = None, **kwargs: Any) -> Any:
        """Sync invocation — routes through KSwitch governance."""
        if input is not None and not kwargs:
            kwargs = {"input": input} if isinstance(input, str) else (input if isinstance(input, dict) else {"input": input})
        result = self._ks_runtime.invoke(self._ks_name, **kwargs)
        return ToolOutput(
            content=str(result),
            tool_name=self._ks_name,
            raw_input=kwargs,
            raw_output=result,
        )

    def call(self, input: Any = None, **kwargs: Any) -> Any:
        """Alias for __call__ — some LlamaIndex versions use .call()."""
        return self.__call__(input=input, **kwargs)

    async def acall(self, input: Any = None, **kwargs: Any) -> Any:
        """Async invocation — routes through KSwitch governance."""
        if input is not None and not kwargs:
            kwargs = {"input": input} if isinstance(input, str) else (input if isinstance(input, dict) else {"input": input})
        runtime = self._ks_runtime
        if hasattr(runtime, "invoke_async"):
            result = await runtime.invoke_async(self._ks_name, **kwargs)  # type: ignore[union-attr]
        else:
            result = runtime.invoke(self._ks_name, **kwargs)
        return ToolOutput(
            content=str(result),
            tool_name=self._ks_name,
            raw_input=kwargs,
            raw_output=result,
        )
