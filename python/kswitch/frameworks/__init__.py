"""KSwitch framework adapters — governed tool wrappers for major AI frameworks.

Each adapter translates a framework's native tool-invocation interface into a
KSwitchRuntime.invoke() call. All existing governance pipeline steps run
unchanged: Cedar/OPA evaluation → obligation blocking → output policy → audit.

Install optional extras for the framework(s) you use:
    pip install kswitch-sdk[langchain]
    pip install kswitch-sdk[openai]
    pip install kswitch-sdk[autogen]
    pip install kswitch-sdk[semantic_kernel]
    pip install kswitch-sdk[llamaindex]

Usage example (LangChain):
    from kswitch.frameworks.langchain import KSwitchLangChainTool

    governed_tool = KSwitchLangChainTool(
        name="read_customer_data",
        description="Reads customer records from CRM",
        func=crm.read_customer_data,
        runtime=kswitch_runtime,
    )
    agent = initialize_agent(tools=[governed_tool], llm=llm, ...)
"""

from .langchain import KSwitchLangChainTool
from .openai import KSwitchOpenAITool
from .autogen import KSwitchAutoGenTool
from .semantic_kernel import KSwitchSKPlugin
from .llamaindex import KSwitchLlamaIndexTool
from .anthropic import KSwitchAnthropicClient

__all__ = [
    "KSwitchLangChainTool",
    "KSwitchOpenAITool",
    "KSwitchAutoGenTool",
    "KSwitchSKPlugin",
    "KSwitchLlamaIndexTool",
    "KSwitchAnthropicClient",
]
