"""Postgres implementation of :class:`BaseStorage`.

Uses SQLAlchemy 2.0 async with the ``psycopg`` driver (Postgres async
v3). Reuses the same database that hosts Agno's own tables; the
``dcp_*`` prefix on every table avoids collisions.

Activate by installing the optional extra::

    pip install agno-dcp[postgres]

This module imports ``psycopg`` lazily; importing the package without
``psycopg`` installed will not crash, but instantiating
:class:`PostgresStorage` will raise :class:`StorageError`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agno_dcp.exceptions import StorageError
from agno_dcp.storage.base import BaseStorage


class PostgresStorage(BaseStorage):
    """Postgres-backed storage using SQLAlchemy 2.0 async.

    The ``database_url`` must use the ``postgresql+psycopg://`` scheme,
    e.g. ``postgresql+psycopg://user:pass@host:5432/dbname``. The
    ``initialize()`` method runs the bundled idempotent schema.
    """

    def __init__(self, database_url: str) -> None:
        if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise StorageError(
                "PostgresStorage requires a postgresql:// URL "
                "(scheme postgresql+psycopg:// recommended)"
            )
        try:
            from sqlalchemy.ext.asyncio import (
                AsyncEngine,
                async_sessionmaker,
                create_async_engine,
            )
        except ImportError as exc:  # pragma: no cover
            raise StorageError(
                "PostgresStorage requires sqlalchemy>=2.0. "
                "Install with: pip install agno-dcp[postgres]"
            ) from exc

        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

        self._engine: AsyncEngine = create_async_engine(database_url, echo=False)
        self._sessionmaker = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialize(self) -> None:
        from sqlalchemy import text

        schema_path = Path(__file__).parent / "schema.sql"
        ddl = schema_path.read_text(encoding="utf-8")
        # Strip BEGIN/COMMIT, the engine handles transactions itself.
        statements = [
            s.strip()
            for s in ddl.split(";")
            if s.strip() and s.strip().upper() not in {"BEGIN", "COMMIT"}
        ]
        async with self._engine.begin() as conn:
            for stmt in statements:
                await conn.execute(text(stmt))

    async def close(self) -> None:
        await self._engine.dispose()

    # ── Citizenship Bundles ───────────────────────────────────────

    async def put_citizenship_bundle(self, bundle: dict[str, Any]) -> None:
        from sqlalchemy import text

        agent_id = bundle.get("agent_id")
        bundle_id = bundle.get("bundle_id")
        if not agent_id or not bundle_id:
            raise StorageError("CitizenshipBundle requires agent_id and bundle_id")

        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO dcp_citizenship_bundles "
                    "(agent_id, bundle_id, payload) "
                    "VALUES (:agent_id, :bundle_id, CAST(:payload AS JSONB)) "
                    "ON CONFLICT (agent_id) DO UPDATE SET "
                    "  bundle_id = EXCLUDED.bundle_id, "
                    "  payload = EXCLUDED.payload"
                ),
                {
                    "agent_id": agent_id,
                    "bundle_id": bundle_id,
                    "payload": json.dumps(bundle),
                },
            )

    async def get_citizenship_bundle(self, agent_id: str) -> dict[str, Any] | None:
        from sqlalchemy import text

        async with self._engine.connect() as conn:
            result = await conn.execute(
                text("SELECT payload FROM dcp_citizenship_bundles WHERE agent_id = :a"),
                {"a": agent_id},
            )
            row = result.first()
        if row is None:
            return None
        payload = row[0]
        if isinstance(payload, str):
            return json.loads(payload)  # type: ignore[no-any-return]
        return payload  # type: ignore[no-any-return]

    # ── Intents ───────────────────────────────────────────────────

    async def put_intent(self, intent: dict[str, Any]) -> None:
        from sqlalchemy import text

        async with self._engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO dcp_intents (agent_id, payload) VALUES (:a, CAST(:p AS JSONB))"),
                {"a": intent.get("agent_id", ""), "p": json.dumps(intent)},
            )

    # ── Policy Decisions ──────────────────────────────────────────

    async def put_policy_decision(self, decision: dict[str, Any]) -> None:
        from sqlalchemy import text

        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO dcp_policy_decisions "
                    "(agent_id, approved, payload) "
                    "VALUES (:a, :ok, CAST(:p AS JSONB))"
                ),
                {
                    "a": decision.get("agent_id", ""),
                    "ok": bool(decision.get("approved")),
                    "p": json.dumps(decision),
                },
            )

    # ── Audit Chain ───────────────────────────────────────────────

    async def append_audit_entry(self, entry: dict[str, Any]) -> int:
        from sqlalchemy import text

        required = ("event_type", "payload", "prev_hash", "entry_hash")
        missing = [k for k in required if k not in entry]
        if missing:
            raise StorageError(f"Audit entry missing fields: {missing}")
        payload = entry["payload"]
        if not isinstance(payload, str):
            payload = json.dumps(payload)

        async with self._engine.begin() as conn:
            result = await conn.execute(
                text(
                    "INSERT INTO dcp_audit_chain "
                    "(agent_id, event_type, payload, prev_hash, entry_hash) "
                    "VALUES (:a, :et, CAST(:p AS JSONB), :ph, :eh) "
                    "RETURNING entry_index"
                ),
                {
                    "a": entry.get("agent_id"),
                    "et": entry["event_type"],
                    "p": payload,
                    "ph": entry["prev_hash"],
                    "eh": entry["entry_hash"],
                },
            )
            row = result.first()
        return int(row[0]) if row else 0

    async def get_audit_entries(
        self,
        agent_id: str | None = None,
        start: int = 0,
        end: int | None = None,
    ) -> list[dict[str, Any]]:
        from sqlalchemy import text

        params: dict[str, Any] = {"start": start}
        sql = "SELECT * FROM dcp_audit_chain WHERE entry_index >= :start"
        if agent_id is not None:
            sql += " AND agent_id = :agent_id"
            params["agent_id"] = agent_id
        if end is not None:
            sql += " AND entry_index < :end"
            params["end"] = end
        sql += " ORDER BY entry_index ASC"

        async with self._engine.connect() as conn:
            result = await conn.execute(text(sql), params)
            rows = result.mappings().all()
        return [dict(r) for r in rows]

    async def get_last_audit_entry(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        from sqlalchemy import text

        if agent_id is None:
            sql = "SELECT * FROM dcp_audit_chain ORDER BY entry_index DESC LIMIT 1"
            params: dict[str, Any] = {}
        else:
            sql = (
                "SELECT * FROM dcp_audit_chain WHERE agent_id = :a "
                "ORDER BY entry_index DESC LIMIT 1"
            )
            params = {"a": agent_id}

        async with self._engine.connect() as conn:
            result = await conn.execute(text(sql), params)
            row = result.mappings().first()
        return dict(row) if row else None

    async def put_audit_root(self, root: dict[str, Any]) -> None:
        from sqlalchemy import text

        if not root.get("root_hash"):
            raise StorageError("Audit root requires root_hash")

        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO dcp_audit_roots "
                    "(agent_id, root_hash, entry_count, signature_b64, "
                    " signer_public_key_b64) "
                    "VALUES (:a, :rh, :ec, :sig, :pk)"
                ),
                {
                    "a": root.get("agent_id"),
                    "rh": root["root_hash"],
                    "ec": int(root.get("entry_count", 0)),
                    "sig": root.get("signature_b64", ""),
                    "pk": root.get("signer_public_key_b64", ""),
                },
            )

    async def get_latest_audit_root(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        from sqlalchemy import text

        if agent_id is None:
            sql = (
                "SELECT * FROM dcp_audit_roots WHERE agent_id IS NULL ORDER BY root_id DESC LIMIT 1"
            )
            params: dict[str, Any] = {}
        else:
            sql = "SELECT * FROM dcp_audit_roots WHERE agent_id = :a ORDER BY root_id DESC LIMIT 1"
            params = {"a": agent_id}

        async with self._engine.connect() as conn:
            result = await conn.execute(text(sql), params)
            row = result.mappings().first()
        return dict(row) if row else None
