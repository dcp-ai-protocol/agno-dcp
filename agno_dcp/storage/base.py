"""Abstract storage interface for agno-dcp.

Every concrete backend (sqlite, Postgres, in-memory) implements this
contract. The contract is intentionally narrow: identity lookup,
audit-chain append-and-read, root signature persistence, plus
auxiliary intent and policy-decision tables for forensic queries.

All methods are async. Backends that wrap a synchronous driver should
internally use ``asyncio.to_thread`` rather than blocking the loop.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseStorage(ABC):
    """Persistence contract for agno-dcp.

    Implementations must be safe to call concurrently from multiple
    asyncio tasks. They are NOT required to be safe across processes;
    callers needing multi-process safety should use Postgres.
    """

    @abstractmethod
    async def initialize(self) -> None:
        """Create tables if they do not exist. Idempotent."""

    @abstractmethod
    async def close(self) -> None:
        """Release any held resources (connections, file handles)."""

    # ── Citizenship Bundles (DCP-01) ──────────────────────────────

    @abstractmethod
    async def put_citizenship_bundle(self, bundle: dict[str, Any]) -> None:
        """Insert or replace a Citizenship Bundle indexed by ``agent_id``."""

    @abstractmethod
    async def get_citizenship_bundle(self, agent_id: str) -> dict[str, Any] | None:
        """Fetch a bundle by ``agent_id``. Returns ``None`` if absent."""

    # ── Intent Declarations (DCP-02) ──────────────────────────────

    @abstractmethod
    async def put_intent(self, intent: dict[str, Any]) -> None:
        """Persist a signed Intent Declaration for forensic queries."""

    # ── Policy Decisions (DCP-02) ─────────────────────────────────

    @abstractmethod
    async def put_policy_decision(self, decision: dict[str, Any]) -> None:
        """Persist a signed Policy Decision (allow / deny + reason)."""

    # ── Audit Chain (DCP-03) ──────────────────────────────────────

    @abstractmethod
    async def append_audit_entry(self, entry: dict[str, Any]) -> int:
        """Append an audit entry. Returns the assigned monotonically
        increasing index (entry_index)."""

    @abstractmethod
    async def get_audit_entries(
        self,
        agent_id: str | None = None,
        start: int = 0,
        end: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch audit entries in index order.

        ``agent_id`` filters to a single agent's chain; ``None`` means
        the global cross-agent chain. ``start`` is inclusive, ``end``
        exclusive (Python slice semantics). ``end=None`` means up to
        the latest entry.
        """

    @abstractmethod
    async def get_last_audit_entry(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the most recent audit entry, used to compute
        ``prev_hash`` for the next append. Returns ``None`` for an
        empty chain."""

    @abstractmethod
    async def put_audit_root(self, root: dict[str, Any]) -> None:
        """Persist a signed Merkle root snapshot."""

    @abstractmethod
    async def get_latest_audit_root(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return the most recently sealed root for verification."""
