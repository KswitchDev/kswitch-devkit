"""Canonical MCP tool descriptor hashing for the standalone DevKit MCP package."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Final

MCP_TOOL_FIELD_ORDER: Final[tuple[str, ...]] = (
    "name",
    "description",
    "inputSchema",
    "annotations",
    "version",
)


def build_canonical_tool_spec(
    name: str,
    description: str | None = None,
    input_schema: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    """Build the five-field MCP tool descriptor shape used for drift hashes."""
    return {
        "name": name,
        "description": description if description is not None else "",
        "inputSchema": input_schema if input_schema is not None else {},
        "annotations": annotations,
        "version": version if version is not None else "",
    }


def canonical_tool_spec(spec: dict[str, Any]) -> bytes:
    """Return stable JSON bytes for an MCP tool descriptor."""
    if not isinstance(spec, dict):
        raise TypeError(
            f"canonical_tool_spec requires dict input, got {type(spec).__name__}"
        )
    text = json.dumps(
        spec,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def compute_descriptor_hash(spec: dict[str, Any]) -> str:
    """Return the SHA-256 hex digest of the canonical descriptor."""
    return hashlib.sha256(canonical_tool_spec(spec)).hexdigest()
