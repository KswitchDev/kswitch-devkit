"""KSwitch adapter for OpenAI function/tool calling.

Wraps a Python callable as an OpenAI tool definition with full KSwitch governance.
The tool schema is auto-generated from the function's type annotations and docstring,
or provided explicitly. All invocations route through KSwitchRuntime.invoke().

Requires: pip install kswitch-sdk[openai]

Usage:
    from kswitch.frameworks.openai import KSwitchOpenAITool

    tool = KSwitchOpenAITool(
        name="send_email",
        description="Send an email to a recipient",
        parameters={
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
        func=email.send,
        runtime=kswitch_runtime,
    )

    # Get the OpenAI tool schema
    response = openai_client.chat.completions.create(
        model="gpt-4",
        messages=messages,
        tools=[tool.schema],
    )

    # Execute a tool call returned by the model
    result = tool.execute(response.choices[0].message.tool_calls[0])
"""

from __future__ import annotations

import json
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..invoke import KSwitchRuntime


class KSwitchOpenAITool:
    """OpenAI tool wrapper with KSwitch governance.

    Provides:
      - .schema: OpenAI-compatible tool definition dict for the tools= parameter
      - .execute(tool_call): Execute an OpenAI ToolCall with full governance
      - .invoke(**kwargs): Direct invocation with full governance
    """

    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        func: Callable[..., Any],
        runtime: "KSwitchRuntime",
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters
        self._func = func
        self._runtime = runtime
        # Register with runtime
        runtime.register(name, func)

    @property
    def schema(self) -> dict[str, Any]:
        """OpenAI-compatible tool definition for use in the tools= parameter."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def execute(self, tool_call: Any) -> str:
        """Execute an OpenAI ToolCall object with full KSwitch governance.

        Args:
            tool_call: A ChatCompletionMessageToolCall from the OpenAI response.

        Returns:
            JSON string of the governed result.
        """
        kwargs = json.loads(tool_call.function.arguments)
        result = self._runtime.invoke(self.name, **kwargs)
        return json.dumps(result) if not isinstance(result, str) else result

    def invoke(self, **kwargs: Any) -> Any:
        """Direct governed invocation (for non-tool-call usage)."""
        return self._runtime.invoke(self.name, **kwargs)
