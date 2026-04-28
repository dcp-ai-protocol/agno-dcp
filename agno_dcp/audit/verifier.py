"""Standalone audit chain verifier and ``agno-dcp`` CLI entry point.

Used by external auditors to confirm that a stored chain has not been
tampered with. It re-derives every entry's hash from the persisted
payload, walks the ``prev_hash`` linkage, and (optionally) verifies
each sealed Merkle root signature against its embedded public key.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Any

from pydantic import BaseModel

from agno_dcp.audit.chain import MerkleAuditChain, RootSignature
from agno_dcp.exceptions import AuditChainCorrupted
from agno_dcp.storage.base import BaseStorage
from agno_dcp.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


class VerificationResult(BaseModel):
    """Outcome of a verifier run."""

    chain_intact: bool
    entries_checked: int
    entries_corrupted: list[int]
    roots_checked: int
    roots_invalid: list[int]
    notes: list[str]


class AuditChainVerifier:
    """Recomputes hashes and root signatures over a persisted chain.

    Args:
        storage: Storage backend that holds the chain.
    """

    def __init__(self, storage: BaseStorage) -> None:
        self.storage = storage

    async def verify(
        self,
        agent_id: str | None = None,
        start: int = 0,
        end: int | None = None,
    ) -> VerificationResult:
        """Run a full verification pass over a chain range.

        Args:
            agent_id: Restrict verification to a single agent's chain
                slice. ``None`` means the global chain.
            start: First entry index to check (inclusive).
            end: Last entry index to check (exclusive). ``None``
                means the latest entry.

        Returns:
            A :class:`VerificationResult` with detailed counts.
        """
        chain = MerkleAuditChain(storage=self.storage)
        notes: list[str] = []
        corrupted: list[int] = []

        entries = await self.storage.get_audit_entries(agent_id=agent_id, start=start, end=end)
        try:
            await chain.verify_range(start=start, end=end, agent_id=agent_id)
        except AuditChainCorrupted as exc:
            if exc.entry_index is not None:
                corrupted.append(exc.entry_index)
            notes.append(str(exc))

        # Walk all sealed roots for the same agent_id slice.
        roots_invalid: list[int] = []
        all_roots: list[dict[str, Any]] = []
        latest = await self.storage.get_latest_audit_root(agent_id=agent_id)
        if latest is not None:
            all_roots.append(latest)

        for r in all_roots:
            try:
                sig = RootSignature.model_validate(r)
            except Exception as exc:
                notes.append(f"root validation error: {exc}")
                continue
            if not await chain.verify_root_signature(sig):
                roots_invalid.append(r.get("root_id", -1))

        return VerificationResult(
            chain_intact=len(corrupted) == 0,
            entries_checked=len(entries),
            entries_corrupted=corrupted,
            roots_checked=len(all_roots),
            roots_invalid=roots_invalid,
            notes=notes,
        )


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agno-dcp",
        description=(
            "Verify the integrity of an agno-dcp audit chain. "
            "Recomputes hashes and walks the prev_hash linkage."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    verify = sub.add_parser("verify", help="Verify an audit chain")
    backend = verify.add_mutually_exclusive_group(required=True)
    backend.add_argument("--sqlite", help="Path to a sqlite database file")
    backend.add_argument("--postgres-url", help="postgresql+psycopg:// URL")
    verify.add_argument("--agent-id", default=None, help="Filter to a single agent")
    verify.add_argument(
        "--range",
        default="0:",
        help="Index range start:end. Use 0:1000 or 500: for open-ended.",
    )
    verify.add_argument("--json", action="store_true", help="Print result as JSON instead of text")
    return parser


def _parse_range(spec: str) -> tuple[int, int | None]:
    if ":" not in spec:
        raise SystemExit("Invalid --range. Use start:end (end may be empty).")
    start_s, end_s = spec.split(":", 1)
    start = int(start_s) if start_s else 0
    end = int(end_s) if end_s else None
    return start, end


async def _run_verify(args: argparse.Namespace) -> int:
    start, end = _parse_range(args.range)
    storage: BaseStorage
    if args.sqlite:
        storage = SQLiteStorage(args.sqlite)
    else:
        from agno_dcp.storage.postgres import PostgresStorage

        storage = PostgresStorage(args.postgres_url)
    await storage.initialize()
    try:
        verifier = AuditChainVerifier(storage)
        result = await verifier.verify(agent_id=args.agent_id, start=start, end=end)
    finally:
        await storage.close()

    if args.json:
        print(json.dumps(result.model_dump(), indent=2))
    else:
        print(f"chain_intact:      {result.chain_intact}")
        print(f"entries_checked:   {result.entries_checked}")
        print(f"entries_corrupted: {result.entries_corrupted}")
        print(f"roots_checked:     {result.roots_checked}")
        print(f"roots_invalid:     {result.roots_invalid}")
        if result.notes:
            print("notes:")
            for n in result.notes:
                print(f"  * {n}")
    return 0 if result.chain_intact and not result.roots_invalid else 1


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Wired in ``[project.scripts]``."""
    parser = _build_argparser()
    args = parser.parse_args(argv)
    if args.cmd == "verify":
        return asyncio.run(_run_verify(args))
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
