"""Local audit JSONL — append-only, deduplicates on event_id at sync time.
Storage: ~/.kswitch/local-audit.jsonl
Rotation: rename to .jsonl.1 at 10 MB
Sync: mark_synced(event_ids) sets synced=True for server-confirmed entries
EP-072, §5.3 local audit layer.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROTATION_BYTES: int = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# LocalAuditEntry dataclass
# ---------------------------------------------------------------------------


@dataclass
class LocalAuditEntry:
    """A single record in the local JSONL audit log.

    All fields are strings for clean JSON serialisation.  ``synced`` flips to
    True after mark_synced() confirms the entry is stored server-side.
    """

    event_id: str       # UUID4, shared with remote audit_log.event_id for deduplication
    ts: str             # ISO-8601 UTC, e.g. "2026-04-23T10:00:00.123456Z"
    agent_id: str
    mcp_server_id: str
    tool_name: str
    decision: str       # "allowed" | "blocked"
    layer: str          # "L2a" | "L2b" | "L1_request" | "L1_response" | "remote"
    reason: str
    synced: bool = False  # True after mark_synced(event_ids) confirms server-side dedup


# ---------------------------------------------------------------------------
# LocalAuditLog class
# ---------------------------------------------------------------------------


class LocalAuditLog:
    """Append-only JSONL audit log stored on the local filesystem.

    Thread-safe via a per-instance Lock.  All public methods swallow
    exceptions — NEVER raises from append(), tail(), pending_sync(), or
    mark_synced().

    Rotation: when the file exceeds 10 MB it is renamed to ``.jsonl.1``
    (overwriting any previous ``.jsonl.1``) and a fresh log is started.
    The rotated file is kept on disk; no entries are dropped.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path: Path = (
            path if path is not None else Path.home() / ".kswitch" / "local-audit.jsonl"
        )
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_dir(self) -> None:
        """Create parent directory if it does not already exist."""
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        """Rename the log file to .jsonl.1 when it exceeds _ROTATION_BYTES.

        Must be called with self._lock held.
        """
        try:
            if self._path.exists() and self._path.stat().st_size > _ROTATION_BYTES:
                rotated = self._path.with_suffix(".jsonl.1")
                self._path.rename(rotated)
                log.info(
                    "local_audit: rotated %s → %s (exceeded %d bytes)",
                    self._path,
                    rotated,
                    _ROTATION_BYTES,
                )
        except Exception as exc:
            log.warning("local_audit: rotation check failed: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, entry: LocalAuditEntry) -> None:
        """Serialise *entry* and append it as a JSON line to the audit file.

        Performs rotation check before writing.  Thread-safe.  Never raises.
        """
        with self._lock:
            try:
                self._ensure_dir()
                self._rotate_if_needed()
                line = json.dumps(dataclasses.asdict(entry), ensure_ascii=False)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except Exception as exc:
                log.warning("local_audit: failed to append entry %s: %s", entry.event_id, exc)

    def tail(self, n: int = 50) -> list[LocalAuditEntry]:
        """Return the last *n* entries from the audit file.

        Skips malformed lines with a warning.  Returns an empty list if the
        file does not exist or on any read error.  Never raises.
        """
        if not self._path.exists():
            return []

        try:
            raw_lines = self._path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            log.warning("local_audit: failed to read log for tail(): %s", exc)
            return []

        results: list[LocalAuditEntry] = []
        for line in raw_lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(LocalAuditEntry(**data))
            except Exception as exc:
                log.warning("local_audit: skipping malformed line: %s — %s", line[:80], exc)

        return results

    def pending_sync(self) -> list[LocalAuditEntry]:
        """Return all entries where ``synced == False``.

        Reads the entire file.  Returns an empty list on any error.  Never
        raises.
        """
        if not self._path.exists():
            return []

        try:
            raw_lines = self._path.read_text(encoding="utf-8").splitlines()
        except Exception as exc:
            log.warning("local_audit: failed to read log for pending_sync(): %s", exc)
            return []

        pending: list[LocalAuditEntry] = []
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entry = LocalAuditEntry(**data)
                if not entry.synced:
                    pending.append(entry)
            except Exception as exc:
                log.warning(
                    "local_audit: skipping malformed line in pending_sync(): %s — %s",
                    line[:80],
                    exc,
                )

        return pending

    def mark_synced(self, event_ids: set[str]) -> int:
        """Rewrite the log, setting ``synced=True`` for entries in *event_ids*.

        Thread-safe; acquires the lock for the full rewrite.  Returns the
        count of entries updated.  Returns 0 and logs a warning on any error.
        Never raises.
        """
        with self._lock:
            if not self._path.exists():
                return 0

            try:
                raw_lines = self._path.read_text(encoding="utf-8").splitlines()
            except Exception as exc:
                log.warning("local_audit: failed to read log for mark_synced(): %s", exc)
                return 0

            updated = 0
            new_lines: list[str] = []

            for line in raw_lines:
                stripped = line.strip()
                if not stripped:
                    new_lines.append(line)
                    continue
                try:
                    data = json.loads(stripped)
                    if data.get("event_id") in event_ids and not data.get("synced", False):
                        data["synced"] = True
                        updated += 1
                    new_lines.append(json.dumps(data, ensure_ascii=False))
                except Exception as exc:
                    log.warning(
                        "local_audit: skipping malformed line in mark_synced(): %s — %s",
                        stripped[:80],
                        exc,
                    )
                    new_lines.append(line)

            try:
                # "\n".join() normalises line endings to LF on all platforms,
                # which is the JSONL standard.  On Windows, any CRLF sequences
                # that crept in via a prior write are silently converted to LF
                # here.  This is intentional — the file should always be LF-only.
                self._path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            except Exception as exc:
                log.warning("local_audit: failed to write log in mark_synced(): %s", exc)
                return 0

            return updated


# ---------------------------------------------------------------------------
# Module-level singleton and convenience functions
# ---------------------------------------------------------------------------

_default_log: LocalAuditLog = LocalAuditLog()


def append_entry(entry: LocalAuditEntry) -> None:
    """Append *entry* to the default local audit log."""
    _default_log.append(entry)


def pending_entries() -> list[LocalAuditEntry]:
    """Return all unsynced entries from the default local audit log."""
    return _default_log.pending_sync()


def mark_entries_synced(event_ids: set[str]) -> int:
    """Mark *event_ids* as synced in the default local audit log.

    Returns the count of entries updated.
    """
    return _default_log.mark_synced(event_ids)
