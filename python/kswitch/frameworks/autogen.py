"""KSwitch adapter for AutoGen agents.

Wraps Python callables as governed functions for AutoGen's function_map.
All AutoGen function calls route through KSwitchRuntime.invoke() with full
Cedar evaluation, obligation blocking, output policy, and audit.

Requires: pip install kswitch-sdk[autogen]

Usage:
    from kswitch.frameworks.autogen import KSwitchAutoGenTool, build_autogen_tools

    # Wrap individual functions
    tool = KSwitchAutoGenTool(
        name="execute_sql",
        description="Run a SQL query against the analytics database",
        func=db.execute_sql,
        runtime=kswitch_runtime,
    )

    # Or wrap multiple functions at once
    tools = build_autogen_tools(
        runtime=kswitch_runtime,
        tools={"query_data": db.query, "export_report": reports.export},
    )

    # Use in AutoGen agent
    agent = AssistantAgent(
        name="data_agent",
        llm_config={"tools": [t.llm_config for t in tools]},
    )
    user_proxy = UserProxyAgent(
        name="user_proxy",
        function_map={t.name: t.execute for t in tools},
    )
"""

from __future__ import annotations

from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from ..invoke import KSwitchRuntime


class KSwitchAutoGenTool:
    """AutoGen function wrapper with KSwitch governance.

    Provides:
      - .execute: callable for function_map (routed through governance)
      - .llm_config: dict for llm_config tools= list
    """

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        runtime: "KSwitchRuntime",
        parameters: dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self._func = func
        self._runtime = runtime
        self._parameters = parameters or {}
        # Register with runtime
        runtime.register(name, func)

    def execute(self, **kwargs: Any) -> Any:
        """Callable for AutoGen's function_map. Routes through governance."""
        return self._runtime.invoke(self.name, **kwargs)

    @property
    def llm_config(self) -> dict[str, Any]:
        """AutoGen llm_config tool entry for the agent's tools= list."""
        entry: dict[str, Any] = {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
            },
        }
        if self._parameters:
            entry["function"]["parameters"] = self._parameters
        return entry


def build_autogen_tools(
    runtime: "KSwitchRuntime",
    tools: dict[str, Callable[..., Any]],
    descriptions: dict[str, str] | None = None,
) -> list[KSwitchAutoGenTool]:
    """Wrap multiple callables as governed AutoGen tools.

    Args:
        runtime: KSwitchRuntime instance.
        tools: Dict of {name: callable}.
        descriptions: Optional dict of {name: description}.

    Returns:
        List of KSwitchAutoGenTool instances.
    """
    descs = descriptions or {}
    return [
        KSwitchAutoGenTool(
            name=name,
            description=descs.get(name, f"Governed function: {name}"),
            func=func,
            runtime=runtime,
        )
        for name, func in tools.items()
    ]
