"""Tests for KSwitch framework adapters.

Tests run without any framework installed. Each adapter's governance routing
is verified using a mock KSwitchRuntime. When the real framework IS installed,
the framework-specific interface is also tested.

Performance gate: adapter overhead must be ≤ 5ms p99 (measured in test_latency_overhead).
"""

from __future__ import annotations

import time
import unittest
from typing import Any
from unittest.mock import MagicMock, patch


def _make_runtime(return_value: Any = "governed_result") -> MagicMock:
    """Create a mock KSwitchRuntime that returns a fixed value on invoke()."""
    runtime = MagicMock()
    runtime.invoke.return_value = return_value
    runtime.register.return_value = None
    return runtime


def _raw_tool(**kwargs: Any) -> str:
    return f"raw_{kwargs}"


# ── Base adapter ──────────────────────────────────────────────────────────────

class TestBaseAdapter(unittest.TestCase):
    def test_enforce_routes_to_runtime_invoke(self) -> None:
        from kswitch.frameworks._base import KSwitchFrameworkAdapter
        runtime = _make_runtime("ok")
        adapter = KSwitchFrameworkAdapter("my_tool", _raw_tool, runtime)
        result = adapter.enforce(x=1)
        runtime.invoke.assert_called_once_with("my_tool", x=1)
        self.assertEqual(result, "ok")

    def test_registers_with_runtime(self) -> None:
        from kswitch.frameworks._base import KSwitchFrameworkAdapter
        runtime = _make_runtime()
        KSwitchFrameworkAdapter("tool", _raw_tool, runtime)
        runtime.register.assert_called_once_with("tool", _raw_tool)


# ── OpenAI adapter (no external dep needed) ───────────────────────────────────

class TestOpenAITool(unittest.TestCase):
    def _make_tool(self) -> Any:
        from kswitch.frameworks.openai import KSwitchOpenAITool
        runtime = _make_runtime("query_result")
        return KSwitchOpenAITool(
            name="query_db",
            description="Query database",
            parameters={"type": "object", "properties": {"q": {"type": "string"}}},
            func=_raw_tool,
            runtime=runtime,
        ), runtime

    def test_schema_structure(self) -> None:
        tool, _ = self._make_tool()
        schema = tool.schema
        self.assertEqual(schema["type"], "function")
        self.assertEqual(schema["function"]["name"], "query_db")
        self.assertIn("parameters", schema["function"])

    def test_invoke_routes_through_governance(self) -> None:
        tool, runtime = self._make_tool()
        result = tool.invoke(q="SELECT 1")
        runtime.invoke.assert_called_once_with("query_db", q="SELECT 1")
        self.assertEqual(result, "query_result")

    def test_execute_tool_call_parses_json(self) -> None:
        import json
        tool, runtime = self._make_tool()
        mock_tool_call = MagicMock()
        mock_tool_call.function.arguments = json.dumps({"q": "SELECT *"})
        result = tool.execute(mock_tool_call)
        runtime.invoke.assert_called_once_with("query_db", q="SELECT *")
        self.assertIsInstance(result, str)

    def test_registers_with_runtime(self) -> None:
        tool, runtime = self._make_tool()
        runtime.register.assert_called_once_with("query_db", _raw_tool)


# ── AutoGen adapter ────────────────────────────────────────────────────────────

class TestAutoGenTool(unittest.TestCase):
    def test_execute_routes_through_governance(self) -> None:
        from kswitch.frameworks.autogen import KSwitchAutoGenTool
        runtime = _make_runtime("autogen_result")
        tool = KSwitchAutoGenTool("run_sql", "Run SQL", _raw_tool, runtime)
        result = tool.execute(query="SELECT 1")
        runtime.invoke.assert_called_once_with("run_sql", query="SELECT 1")
        self.assertEqual(result, "autogen_result")

    def test_llm_config_structure(self) -> None:
        from kswitch.frameworks.autogen import KSwitchAutoGenTool
        runtime = _make_runtime()
        tool = KSwitchAutoGenTool("run_sql", "Run SQL", _raw_tool, runtime)
        cfg = tool.llm_config
        self.assertEqual(cfg["type"], "function")
        self.assertEqual(cfg["function"]["name"], "run_sql")

    def test_build_autogen_tools(self) -> None:
        from kswitch.frameworks.autogen import build_autogen_tools
        runtime = _make_runtime()
        tools = build_autogen_tools(runtime, {"tool_a": _raw_tool, "tool_b": _raw_tool})
        self.assertEqual(len(tools), 2)
        names = {t.name for t in tools}
        self.assertEqual(names, {"tool_a", "tool_b"})


# ── LangChain adapter (framework-optional) ────────────────────────────────────

class TestLangChainTool(unittest.TestCase):
    def test_import_error_without_langchain(self) -> None:
        """Without langchain installed, instantiation raises ImportError."""
        from kswitch.frameworks import langchain as lc_mod
        original = lc_mod._LANGCHAIN_AVAILABLE
        try:
            lc_mod._LANGCHAIN_AVAILABLE = False
            with self.assertRaises(ImportError):
                lc_mod.KSwitchLangChainTool(
                    name="t", description="d", func=_raw_tool, runtime=_make_runtime()
                )
        finally:
            lc_mod._LANGCHAIN_AVAILABLE = original

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("langchain") is not None,
        "langchain not installed"
    )
    def test_run_routes_through_governance(self) -> None:
        from kswitch.frameworks.langchain import KSwitchLangChainTool
        runtime = _make_runtime("lc_result")
        tool = KSwitchLangChainTool(
            name="lc_tool", description="LC test", func=_raw_tool, runtime=runtime
        )
        result = tool._run(x=1)
        runtime.invoke.assert_called_once_with("lc_tool", x=1)
        self.assertEqual(result, "lc_result")


# ── LlamaIndex adapter (framework-optional) ───────────────────────────────────

class TestLlamaIndexTool(unittest.TestCase):
    def test_import_error_without_llamaindex(self) -> None:
        from kswitch.frameworks import llamaindex as li_mod
        original = li_mod._LLAMA_AVAILABLE
        try:
            li_mod._LLAMA_AVAILABLE = False
            with self.assertRaises(ImportError):
                li_mod.KSwitchLlamaIndexTool(
                    name="t", description="d", func=_raw_tool, runtime=_make_runtime()
                )
        finally:
            li_mod._LLAMA_AVAILABLE = original

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("llama_index") is not None,
        "llama-index not installed"
    )
    def test_call_routes_through_governance(self) -> None:
        from kswitch.frameworks.llamaindex import KSwitchLlamaIndexTool
        runtime = _make_runtime("li_result")
        tool = KSwitchLlamaIndexTool(
            name="li_tool", description="LI test", func=_raw_tool, runtime=runtime
        )
        result = tool("search query")
        runtime.invoke.assert_called_once_with("li_tool", input="search query")


# ── Semantic Kernel adapter (framework-optional) ──────────────────────────────

class TestSKPlugin(unittest.TestCase):
    def test_import_error_without_sk(self) -> None:
        from kswitch.frameworks import semantic_kernel as sk_mod
        original = sk_mod._SK_AVAILABLE
        try:
            sk_mod._SK_AVAILABLE = False
            with self.assertRaises(ImportError):
                sk_mod.KSwitchSKPlugin(
                    plugin_name="p",
                    runtime=_make_runtime(),
                    functions={"f": (_raw_tool, "desc")},
                )
        finally:
            sk_mod._SK_AVAILABLE = original

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("semantic_kernel") is not None,
        "semantic-kernel not installed"
    )
    def test_plugin_functions_attached(self) -> None:
        from kswitch.frameworks.semantic_kernel import KSwitchSKPlugin
        runtime = _make_runtime()
        plugin = KSwitchSKPlugin(
            plugin_name="TestPlugin",
            runtime=runtime,
            functions={"lookup": (_raw_tool, "Look up data")},
        )
        self.assertTrue(hasattr(plugin, "lookup"))


# ── Performance gate: adapter overhead ≤ 5ms p99 ─────────────────────────────

class TestLatencyOverhead(unittest.TestCase):
    def test_adapter_overhead_under_5ms_p99(self) -> None:
        """Adapter overhead (excluding runtime.invoke() latency) must be ≤ 5ms p99.

        We mock invoke() to return instantly (no enforcement latency), then measure
        the pure wrapper overhead over 100 calls. p99 must be < 5ms.
        """
        from kswitch.frameworks._base import KSwitchFrameworkAdapter
        runtime = MagicMock()
        runtime.invoke.return_value = "result"
        runtime.register.return_value = None
        adapter = KSwitchFrameworkAdapter("bench_tool", _raw_tool, runtime)

        latencies = []
        for _ in range(100):
            t0 = time.perf_counter()
            adapter.enforce(x=1)
            latencies.append((time.perf_counter() - t0) * 1000)  # ms

        latencies.sort()
        p99 = latencies[98]  # 99th percentile of 100 samples
        self.assertLess(p99, 5.0, f"Adapter p99 overhead = {p99:.3f}ms, must be < 5ms")


if __name__ == "__main__":
    unittest.main()
