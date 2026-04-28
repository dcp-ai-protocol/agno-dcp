"""SQLite implementation of :class:`BaseStorage`.

Uses the stdlib ``sqlite3`` module wrapped in ``asyncio.to_thread`` so
it does not pull in extra dependencies. Suitable for development,
local tests, and small single-process deployments. For multi-process
or high-throughput production traffic, switch to
:class:`agno_dcp.storage.postgres.PostgresStorage`.

The schema is intentionally identical in shape to the Postgres
schema (see ``schema.sql``) so a SQLite-developed app can be moved to
Postgres with no application changes.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC
from pathlib import Path
from typing import Any

from agno_dcp.exceptions import StorageError
from agno_dcp.storage.base import BaseStorage

_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS dcp_citizenship_bundles (
    agent_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dcp_intents (
    intent_id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dcp_intents_agent ON dcp_intents(agent_id);

CREATE TABLE IF NOT EXISTS dcp_policy_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    approved INTEGER NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dcp_decisions_agent ON dcp_policy_decisions(agent_id);

CREATE TABLE IF NOT EXISTS dcp_audit_chain (
    entry_index INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dcp_audit_agent ON dcp_audit_chain(agent_id);

CREATE TABLE IF NOT EXISTS dcp_audit_roots (
    root_id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    root_hash TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    signature_b64 TEXT NOT NULL,
    signer_public_key_b64 TEXT NOT NULL,
    sealed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dcp_roots_agent ON dcp_audit_roots(agent_id);
"""


class SQLiteStorage(BaseStorage):
    """File-backed SQLite storage for development and small deployments.

    Args:
        path: Path to the SQLite database file. Use ``:memory:`` for
            an in-memory database (useful for tests).
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._lock = asyncio.Lock()
        self._conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        """Get or create the underlying connection.

        SQLite connections are not safe across threads by default;
        we serialize all access through ``self._lock``.
        """
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.path,
                isolation_level=None,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _executescript_sync(self, ddl: str) -> None:
        conn = self._connect()
        conn.executescript(ddl)

    async def initialize(self) -> None:
        async with self._lock:
            await asyncio.to_thread(self._executescript_sync, _SCHEMA_DDL)

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                conn = self._conn
                self._conn = None
                await asyncio.to_thread(conn.close)

    # ── helpers ───────────────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        from datetime import datetime

        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return {k: row[k] for k in row.keys()}

    # ── Citizenship Bundles ───────────────────────────────────────

    async def put_citizenship_bundle(self, bundle: dict[str, Any]) -> None:
        agent_id = bundle.get("agent_id")
        bundle_id = bundle.get("bundle_id")
        if not agent_id or not bundle_id:
            raise StorageError("CitizenshipBundle requires agent_id and bundle_id")
        payload = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
        now = self._now()

        def _do() -> None:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO dcp_citizenship_bundles "
                "(agent_id, bundle_id, payload, created_at) VALUES (?,?,?,?)",
                (agent_id, bundle_id, payload, now),
            )

        async with self._lock:
            await asyncio.to_thread(_do)

    async def get_citizenship_bundle(self, agent_id: str) -> dict[str, Any] | None:
        def _do() -> sqlite3.Row | None:
            conn = self._connect()
            cur = conn.execute(
                "SELECT payload FROM dcp_citizenship_bundles WHERE agent_id = ?",
                (agent_id,),
            )
            row: sqlite3.Row | None = cur.fetchone()
            return row

        async with self._lock:
            row = await asyncio.to_thread(_do)
        if row is None:
            return None
        return json.loads(row["payload"])  # type: ignore[no-any-return]

    # ── Intents ───────────────────────────────────────────────────

    async def put_intent(self, intent: dict[str, Any]) -> None:
        agent_id = intent.get("agent_id", "")
        payload = json.dumps(intent, sort_keys=True, separators=(",", ":"))
        now = self._now()

        def _do() -> None:
            conn = self._connect()
            conn.execute(
                "INSERT INTO dcp_intents (agent_id, payload, created_at) VALUES (?,?,?)",
                (agent_id, payload, now),
            )

        async with self._lock:
            await asyncio.to_thread(_do)

    # ── Policy Decisions ──────────────────────────────────────────

    async def put_policy_decision(self, decision: dict[str, Any]) -> None:
        agent_id = decision.get("agent_id", "")
        approved = 1 if decision.get("approved") else 0
        payload = json.dumps(decision, sort_keys=True, separators=(",", ":"))
        now = self._now()

        def _do() -> None:
            conn = self._connect()
            conn.execute(
                "INSERT INTO dcp_policy_decisions "
                "(agent_id, approved, payload, created_at) VALUES (?,?,?,?)",
                (agent_id, approved, payload, now),
            )

        async with self._lock:
            await asyncio.to_thread(_do)

    # ── Audit Chain ───────────────────────────────────────────────

    async def append_audit_entry(self, entry: dict[str, Any]) -> int:
        required = ("event_type", "payload", "prev_hash", "entry_hash")
        missing = [k for k in required if k not in entry]
        if missing:
            raise StorageError(f"Audit entry missing fields: {missing}")
        agent_id = entry.get("agent_id")
        event_type = entry["event_type"]
        payload = entry["payload"]
        if not isinstance(payload, str):
            payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        prev_hash = entry["prev_hash"]
        entry_hash = entry["entry_hash"]
        now = self._now()

        def _do() -> int:
            conn = self._connect()
            cur = conn.execute(
                "INSERT INTO dcp_audit_chain "
                "(agent_id, event_type, payload, prev_hash, entry_hash, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (agent_id, event_type, payload, prev_hash, entry_hash, now),
            )
            return int(cur.lastrowid or 0)

        async with self._lock:
            return await asyncio.to_thread(_do)

    async def get_audit_entries(
        self,
        agent_id: str | None = None,
        start: int = 0,
        end: int | None = None,
    ) -> list[dict[str, Any]]:
        def _do() -> list[sqlite3.Row]:
            conn = self._connect()
            if agent_id is None:
                if end is None:
                    cur = conn.execute(
                        "SELECT * FROM dcp_audit_chain WHERE entry_index >= ? "
                        "ORDER BY entry_index ASC",
                        (start,),
                    )
                else:
                    cur = conn.execute(
                        "SELECT * FROM dcp_audit_chain WHERE entry_index >= ? "
                        "AND entry_index < ? ORDER BY entry_index ASC",
                        (start, end),
                    )
            else:
                if end is None:
                    cur = conn.execute(
                        "SELECT * FROM dcp_audit_chain WHERE agent_id = ? "
                        "AND entry_index >= ? ORDER BY entry_index ASC",
                        (agent_id, start),
                    )
                else:
                    cur = conn.execute(
                        "SELECT * FROM dcp_audit_chain WHERE agent_id = ? "
                        "AND entry_index >= ? AND entry_index < ? "
                        "ORDER BY entry_index ASC",
                        (agent_id, start, end),
                    )
            rows: list[sqlite3.Row] = cur.fetchall()
            return rows

        async with self._lock:
            rows = await asyncio.to_thread(_do)
        result = []
        for row in rows:
            d = {k: row[k] for k in row.keys()}
            try:
                d["payload"] = json.loads(d["payload"])
            except (TypeError, json.JSONDecodeError):
                pass
            result.append(d)
        return result

    async def get_last_audit_entry(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        def _do() -> sqlite3.Row | None:
            conn = self._connect()
            if agent_id is None:
                cur = conn.execute(
                    "SELECT * FROM dcp_audit_chain ORDER BY entry_index DESC LIMIT 1"
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM dcp_audit_chain WHERE agent_id = ? "
                    "ORDER BY entry_index DESC LIMIT 1",
                    (agent_id,),
                )
            row: sqlite3.Row | None = cur.fetchone()
            return row

        async with self._lock:
            row = await asyncio.to_thread(_do)
        if row is None:
            return None
        d = {k: row[k] for k in row.keys()}
        try:
            d["payload"] = json.loads(d["payload"])
        except (TypeError, json.JSONDecodeError):
            pass
        return d

    async def put_audit_root(self, root: dict[str, Any]) -> None:
        agent_id = root.get("agent_id")
        root_hash = root.get("root_hash")
        entry_count = root.get("entry_count", 0)
        signature_b64 = root.get("signature_b64", "")
        signer_pk = root.get("signer_public_key_b64", "")
        if not root_hash:
            raise StorageError("Audit root requires root_hash")
        now = self._now()

        def _do() -> None:
            conn = self._connect()
            conn.execute(
                "INSERT INTO dcp_audit_roots "
                "(agent_id, root_hash, entry_count, signature_b64, "
                "signer_public_key_b64, sealed_at) VALUES (?,?,?,?,?,?)",
                (agent_id, root_hash, entry_count, signature_b64, signer_pk, now),
            )

        async with self._lock:
            await asyncio.to_thread(_do)

    async def get_latest_audit_root(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        def _do() -> sqlite3.Row | None:
            conn = self._connect()
            if agent_id is None:
                cur = conn.execute(
                    "SELECT * FROM dcp_audit_roots WHERE agent_id IS NULL "
                    "ORDER BY root_id DESC LIMIT 1"
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM dcp_audit_roots WHERE agent_id = ? "
                    "ORDER BY root_id DESC LIMIT 1",
                    (agent_id,),
                )
            row: sqlite3.Row | None = cur.fetchone()
            return row

        async with self._lock:
            row = await asyncio.to_thread(_do)
        return self._row_to_dict(row)
