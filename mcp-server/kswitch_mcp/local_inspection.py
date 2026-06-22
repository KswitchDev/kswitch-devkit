"""L1 PIJ (Prompt Injection) inspection engine for the KSwitch MCP proxy embedded local PDP.

Loads and compiles prompt-injection signatures at module import time and exposes
a fast, synchronous ``inspect_content()`` API consumed by the MCP proxy pipeline.

Canonical pattern source: schema/pij-signatures.json
Bundled copy:             kswitch_mcp/data/pij-signatures.json
Drift guard:              scripts/audit-pij-drift.py
EP-072, §5.1 L1 layer
"""

from __future__ import annotations

import importlib.resources
import json
import logging
import os
import re
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level inspection mode — overridden by KSWITCH_LOCAL_INSPECTION_MODE.
# Valid values: "enforce" | "shadow" | "disabled"
# ---------------------------------------------------------------------------
INSPECTION_MODE: str = os.environ.get("KSWITCH_LOCAL_INSPECTION_MODE", "enforce")

# ---------------------------------------------------------------------------
# Size cap (bytes, UTF-8 encoded).
# ---------------------------------------------------------------------------
_SIZE_CAP_BYTES: int = 65536


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class LocalInspectionResult:
    """Result returned by :meth:`LocalInspectionEngine.inspect`."""

    allowed: bool
    matched_signatures: list[dict]
    truncated: bool = False
    mode: str = "enforce"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class LocalInspectionEngine:
    """Compile PIJ patterns at first construction and expose ``inspect()``."""

    _compiled: list[tuple[dict, re.Pattern]] = []
    _raw_patterns: list[dict] = []
    _patterns_loaded: bool = False

    def __init__(self) -> None:
        self._load_patterns()

    # ------------------------------------------------------------------
    # Pattern loading (class-level, called once)
    # ------------------------------------------------------------------

    @classmethod
    def _load_patterns(cls) -> None:
        """Load and compile patterns from the bundled JSON.

        Uses the Python 3.9+ ``importlib.resources.files()`` API with a
        fallback to the older ``importlib.resources.read_text()`` for
        environments running an older stdlib.
        """
        if cls._patterns_loaded:
            return

        raw_text: str | None = None

        # Primary path: Python 3.9+ files() API.
        try:
            import kswitch_mcp  # local import to avoid circular at module level

            raw_text = (
                importlib.resources.files(kswitch_mcp)
                .joinpath("data/pij-signatures.json")
                .read_text(encoding="utf-8")
            )
        except (AttributeError, TypeError, FileNotFoundError):
            # Fallback: legacy read_text() available in Python 3.7+.
            try:
                raw_text = importlib.resources.read_text(  # type: ignore[attr-defined]
                    "kswitch_mcp.data", "pij-signatures.json", encoding="utf-8"
                )
            except Exception as exc:
                log.critical(
                    "local_inspection: failed to load pij-signatures.json via fallback: %s",
                    exc,
                    exc_info=True,
                )

        if raw_text is None:
            log.critical(
                "local_inspection: pij-signatures.json could not be loaded — "
                "L1 inspection will fail-open. Check package installation."
            )
            cls._patterns_loaded = False
            return

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            log.critical(
                "local_inspection: pij-signatures.json is not valid JSON: %s", exc
            )
            cls._patterns_loaded = False
            return

        signatures: list[dict] = data.get("signatures", [])
        compiled: list[tuple[dict, re.Pattern]] = []

        _flag_map: dict[str, int] = {
            "IGNORECASE": re.IGNORECASE,
            "DOTALL": re.DOTALL,
            "MULTILINE": re.MULTILINE,
        }

        for sig in signatures:
            raw_flags: str = sig.get("flags", "")
            combined_flags: int = 0
            if raw_flags:
                for flag_name in raw_flags.split("|"):
                    flag_name = flag_name.strip()
                    if flag_name in _flag_map:
                        combined_flags |= _flag_map[flag_name]
                    else:
                        log.warning(
                            "local_inspection: unknown flag %r in signature %s — skipped",
                            flag_name,
                            sig.get("id"),
                        )

            try:
                pattern = re.compile(sig["pattern"], combined_flags)
            except re.error as exc:
                log.error(
                    "local_inspection: failed to compile pattern for %s: %s — skipped",
                    sig.get("id"),
                    exc,
                )
                continue

            compiled.append((sig, pattern))

        cls._raw_patterns = signatures
        cls._compiled = compiled
        cls._patterns_loaded = True
        log.debug(
            "local_inspection: loaded %d PIJ signatures (%d compiled)",
            len(signatures),
            len(compiled),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, content: str, mode: str = "enforce") -> LocalInspectionResult:
        """Inspect *content* for prompt-injection signatures.

        Parameters
        ----------
        content:
            The text to inspect (e.g. a tool argument or MCP server response).
        mode:
            ``"enforce"`` — block on any match (default).
            ``"shadow"``  — log matches but always allow.
            ``"disabled"`` — skip inspection entirely and allow.

        Returns
        -------
        LocalInspectionResult
        """
        if mode == "disabled":
            return LocalInspectionResult(
                allowed=True,
                matched_signatures=[],
                mode="disabled",
            )

        # Fail-open if patterns failed to load, but warn loudly.
        if not self._patterns_loaded:
            log.warning(
                "local_inspection: patterns not loaded — failing open. "
                "This is a misconfiguration; fix the package installation."
            )
            return LocalInspectionResult(
                allowed=True,
                matched_signatures=[],
                mode="error",
            )

        # ------------------------------------------------------------------
        # 64 KB size cap — truncate and flag if exceeded.
        # ------------------------------------------------------------------
        truncated: bool = False
        encoded = content.encode("utf-8")
        if len(encoded) > _SIZE_CAP_BYTES:
            content = encoded[:_SIZE_CAP_BYTES].decode("utf-8", errors="replace")
            truncated = True
            log.debug(
                "local_inspection: content truncated from %d bytes to %d bytes",
                len(encoded),
                _SIZE_CAP_BYTES,
            )

        # ------------------------------------------------------------------
        # Pattern scan.
        # ------------------------------------------------------------------
        matched: list[dict] = []
        for sig, pattern in self._compiled:
            if pattern.search(content):
                matched.append(
                    {
                        "id": sig["id"],
                        "label": sig["label"],
                        "severity": sig["severity"],
                    }
                )

        # ------------------------------------------------------------------
        # Decision.
        # ------------------------------------------------------------------
        if mode == "shadow":
            if matched:
                log.warning(
                    "local_inspection [shadow]: %d PIJ signature(s) matched — "
                    "allowed because mode=shadow. ids=%s",
                    len(matched),
                    [m["id"] for m in matched],
                )
            return LocalInspectionResult(
                allowed=True,
                matched_signatures=matched,
                truncated=truncated,
                mode="shadow",
            )

        # enforce mode
        if matched:
            log.warning(
                "local_inspection [enforce]: %d PIJ signature(s) matched — blocked. ids=%s",
                len(matched),
                [m["id"] for m in matched],
            )
            return LocalInspectionResult(
                allowed=False,
                matched_signatures=matched,
                truncated=truncated,
                mode="enforce",
            )

        return LocalInspectionResult(
            allowed=True,
            matched_signatures=[],
            truncated=truncated,
            mode="enforce",
        )

    def available_patterns(self) -> list[dict]:
        """Return the raw list of signature dicts from the JSON catalogue."""
        return list(self._raw_patterns)


# ---------------------------------------------------------------------------
# Module-level singleton and convenience wrapper
# ---------------------------------------------------------------------------

_engine = LocalInspectionEngine()


def inspect_content(content: str, mode: str = INSPECTION_MODE) -> LocalInspectionResult:
    """Module-level convenience wrapper around :meth:`LocalInspectionEngine.inspect`.

    Uses the ``INSPECTION_MODE`` constant (from ``KSWITCH_LOCAL_INSPECTION_MODE``)
    as the default *mode*, so callers that don't pass an explicit mode automatically
    pick up the process-wide setting.

    .. important::
        ``INSPECTION_MODE`` is a **module-level constant resolved once at import
        time**.  If ``KSWITCH_LOCAL_INSPECTION_MODE`` changes after the module has
        been imported (e.g. in tests that mutate ``os.environ``), the default will
        NOT update.  Pass ``mode`` explicitly to override on a per-call basis:

        .. code-block:: python

            inspect_content(text, mode=os.environ.get("KSWITCH_LOCAL_INSPECTION_MODE", "enforce"))

        The proxy tool wrapper in ``proxy.py`` does exactly this — it reads the env
        var fresh on every invocation via ``insp_mode`` so runtime reconfiguration
        is honoured without a process restart.
    """
    return _engine.inspect(content, mode=mode)
