"""Hash-chained, Merkle-sealed audit log (DCP-03).

The :class:`MerkleAuditChain` provides three guarantees:

1. **Append-only**: entries are assigned monotonic ``entry_index``
   values by the storage backend. There is no public delete or
   update method.
2. **Hash-chained**: every entry carries a ``prev_hash`` field equal
   to the SHA-256 of the immediately previous entry's canonical form.
   Any tampering with a historical entry breaks the chain.
3. **Merkle-sealed**: ``seal_root()`` computes the Merkle root of the
   current chain and signs it with the audit chain's keypair. The
   signed root can be exported to an auditor for offline verification
   without trusting the storage backend.

Cryptographic primitives (SHA-256, canonicalization, Ed25519 sign and
verify) are imported from the upstream ``dcp_ai`` SDK so that bundles
produced by agno-dcp and verifiers built on the SDK are byte-exact
compatible.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from agno_dcp.exceptions import AuditChainCorrupted, IdentityError

if TYPE_CHECKING:
    from agno_dcp.storage.base import BaseStorage


logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):  # noqa: UP042  (str+Enum for json-serializability across pydantic v2)
    """Closed set of audit event categories.

    Storage backends index on this column so adding a new value
    requires migration. Values are stable strings and form part of the
    signed payload; do not rename.
    """

    AGENT_CREATED = "AGENT_CREATED"
    INTENT_DECLARED = "INTENT_DECLARED"
    POLICY_DECISION = "POLICY_DECISION"
    TOOL_EXECUTED = "TOOL_EXECUTED"
    TEAM_MESSAGE = "TEAM_MESSAGE"
    MCP_INBOUND = "MCP_INBOUND"
    MCP_OUTBOUND = "MCP_OUTBOUND"
    WORKFLOW_STEP = "WORKFLOW_STEP"
    ERROR = "ERROR"


class AuditEvent(BaseModel):
    """An event submitted to the audit chain.

    Attributes:
        event_type: Category of event (see :class:`AuditEventType`).
        agent_id: Optional identifier of the agent that produced the
            event. ``None`` for system or cross-agent events (root
            seals, team-level audits).
        payload: Arbitrary JSON-serializable event body. May contain
            PII; encrypt at the storage layer if needed.
        timestamp: UTC ISO-8601 timestamp. Auto-filled if omitted.
    """

    model_config = ConfigDict(extra="forbid")

    event_type: AuditEventType
    agent_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = ""

    def model_post_init(self, _ctx: Any) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditEntry(BaseModel):
    """A persisted audit chain entry.

    Returned from :meth:`MerkleAuditChain.append`. Carries the
    storage-assigned ``entry_index``, the chain linkage hashes, and
    the original event.
    """

    model_config = ConfigDict(extra="forbid")

    entry_index: int
    event_type: AuditEventType
    agent_id: str | None
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str
    created_at: str

    def to_signable(self) -> dict[str, Any]:
        """Canonical form used to compute :attr:`entry_hash`.

        Excludes ``entry_hash`` itself and storage-assigned timestamp
        so the hash depends only on logically meaningful fields.
        """
        d = self.model_dump()
        d.pop("entry_hash", None)
        d.pop("created_at", None)
        return d


class RootSignature(BaseModel):
    """A signed Merkle root snapshot."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str | None
    root_hash: str
    entry_count: int
    signature_b64: str
    signer_public_key_b64: str
    sealed_at: str


def _import_dcp_primitives() -> tuple[Any, Any, Any, Any, Any]:
    """Lazy import of dcp_ai primitives used by the chain.

    Returns ``(hash_object, generate_keypair, sign_object,
    verify_object, merkle_root_for_audit_entries)``.
    """
    try:
        from dcp_ai.crypto import (
            generate_keypair,
            sign_object,
            verify_object,
        )
        from dcp_ai.merkle import (
            hash_object,
            merkle_root_for_audit_entries,
        )
    except ImportError as exc:  # pragma: no cover
        raise IdentityError(
            "dcp_ai SDK is required for audit operations. "
            "Install it with: pip install dcp-ai>=2.8.1"
        ) from exc
    return (
        hash_object,
        generate_keypair,
        sign_object,
        verify_object,
        merkle_root_for_audit_entries,
    )


class MerkleAuditChain:
    """Hash-chained, Merkle-sealed audit log.

    Args:
        storage: Backend that persists entries and roots.
        signer_secret_key_b64: Optional Ed25519 secret key (base64)
            used to sign root snapshots. If omitted, a fresh keypair
            is generated and exposed via
            :attr:`signer_public_key_b64` so callers can persist it
            externally.
        signer_public_key_b64: Public key matching
            ``signer_secret_key_b64``. Required when secret is
            provided; ignored otherwise.
    """

    def __init__(
        self,
        storage: BaseStorage,
        *,
        signer_secret_key_b64: str | None = None,
        signer_public_key_b64: str | None = None,
    ) -> None:
        self.storage = storage
        (
            self._hash_object,
            generate_keypair,
            self._sign_object,
            self._verify_object,
            self._merkle_root,
        ) = _import_dcp_primitives()

        if signer_secret_key_b64 is None:
            kp = generate_keypair()
            self._signer_secret_b64: str = kp["secret_key_b64"]
            self.signer_public_key_b64: str = kp["public_key_b64"]
        else:
            if not signer_public_key_b64:
                raise IdentityError(
                    "signer_public_key_b64 must be provided alongside signer_secret_key_b64"
                )
            self._signer_secret_b64 = signer_secret_key_b64
            self.signer_public_key_b64 = signer_public_key_b64

    @staticmethod
    def _genesis_hash() -> str:
        """The ``prev_hash`` value used for the very first entry.

        A fixed string rather than an empty value so verifiers can
        unambiguously detect "this is the start of the chain".
        """
        return "GENESIS"

    async def append(self, event: AuditEvent) -> AuditEntry:
        """Append an event to the chain.

        Computes ``prev_hash`` from the most recent entry, then
        computes ``entry_hash`` over the canonical form of the new
        entry, then persists it through the storage backend.

        Args:
            event: The event to append.

        Returns:
            The persisted :class:`AuditEntry` including the
            backend-assigned ``entry_index`` and computed hashes.
        """
        last = await self.storage.get_last_audit_entry(agent_id=None)
        prev_hash = last["entry_hash"] if last else self._genesis_hash()

        # The hash covers the logical content (event_type, agent_id,
        # payload, prev_hash). Timestamps are metadata; including them
        # would force every backend to round microseconds identically
        # to be re-hashable, which is fragile. Chain integrity is
        # preserved by prev_hash linkage plus payload coverage.
        signable = {
            "event_type": event.event_type.value,
            "agent_id": event.agent_id,
            "payload": event.payload,
            "prev_hash": prev_hash,
        }
        entry_hash = self._hash_object(signable)

        record = {
            "agent_id": event.agent_id,
            "event_type": event.event_type.value,
            "payload": event.payload,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }
        entry_index = await self.storage.append_audit_entry(record)

        result = AuditEntry(
            entry_index=entry_index,
            event_type=event.event_type,
            agent_id=event.agent_id,
            payload=event.payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            created_at=event.timestamp,
        )
        logger.debug(
            "Appended audit entry %d type=%s agent=%s",
            entry_index,
            event.event_type.value,
            event.agent_id,
        )
        return result

    async def seal_root(self, agent_id: str | None = None) -> RootSignature:
        """Compute, sign, and persist the current Merkle root.

        Call this periodically (end of session, on a cron, after a
        batch of events) to produce a tamper-evident checkpoint that
        an external auditor can verify offline.

        Args:
            agent_id: If provided, seals only the per-agent slice of
                the chain. If ``None``, seals the full chain.

        Returns:
            The signed :class:`RootSignature`.
        """
        entries = await self.storage.get_audit_entries(agent_id=agent_id)
        if not entries:
            root_hash = self._genesis_hash()
        else:
            # Same projection as ``append`` and ``verify_range`` so the
            # leaf hashes match the stored ``entry_hash`` values.
            signable_entries = [
                {
                    "event_type": e["event_type"],
                    "agent_id": e.get("agent_id"),
                    "payload": e["payload"],
                    "prev_hash": e["prev_hash"],
                }
                for e in entries
            ]
            computed = self._merkle_root(signable_entries)
            root_hash = computed if computed is not None else self._genesis_hash()

        sealed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        root_payload = {
            "agent_id": agent_id,
            "root_hash": root_hash,
            "entry_count": len(entries),
            "sealed_at": sealed_at,
        }
        signature_b64 = self._sign_object(root_payload, self._signer_secret_b64)

        sig = RootSignature(
            agent_id=agent_id,
            root_hash=root_hash,
            entry_count=len(entries),
            signature_b64=signature_b64,
            signer_public_key_b64=self.signer_public_key_b64,
            sealed_at=sealed_at,
        )
        await self.storage.put_audit_root(sig.model_dump())
        logger.info(
            "Sealed audit root agent_id=%s entries=%d",
            agent_id,
            len(entries),
        )
        return sig

    async def verify_range(
        self,
        start: int = 0,
        end: int | None = None,
        agent_id: str | None = None,
    ) -> bool:
        """Recompute hashes for ``[start, end)`` and check the chain.

        Returns ``True`` if every entry's ``entry_hash`` matches the
        recomputed value AND every entry's ``prev_hash`` equals the
        previous entry's ``entry_hash`` (or the genesis sentinel for
        the first entry in the range).

        Raises:
            AuditChainCorrupted: With ``entry_index`` set to the first
                divergence point.
        """
        entries = await self.storage.get_audit_entries(agent_id=agent_id, start=start, end=end)
        if not entries:
            return True

        # The expected prev_hash for the first entry in the range
        # depends on whether this range starts at the chain origin.
        if start == 0:
            expected_prev = self._genesis_hash()
        else:
            prev_entries = await self.storage.get_audit_entries(
                agent_id=agent_id, start=max(0, start - 1), end=start
            )
            if not prev_entries:
                expected_prev = self._genesis_hash()
            else:
                expected_prev = prev_entries[-1]["entry_hash"]

        for e in entries:
            if e["prev_hash"] != expected_prev:
                raise AuditChainCorrupted(
                    f"prev_hash mismatch at entry_index={e['entry_index']}",
                    entry_index=e["entry_index"],
                )
            signable = {
                "event_type": e["event_type"],
                "agent_id": e.get("agent_id"),
                "payload": e["payload"],
                "prev_hash": e["prev_hash"],
            }
            recomputed = self._hash_object(signable)
            if recomputed != e["entry_hash"]:
                raise AuditChainCorrupted(
                    f"entry_hash mismatch at entry_index={e['entry_index']}",
                    entry_index=e["entry_index"],
                )
            expected_prev = e["entry_hash"]
        return True

    async def verify_root_signature(self, root: RootSignature) -> bool:
        """Verify the Ed25519 signature embedded in a root snapshot.

        Returns ``True`` if the signature is valid against the root's
        own ``signer_public_key_b64``. Use this when a root signature
        was produced by an external party and you have its public key
        out of band.
        """
        signable = {
            "agent_id": root.agent_id,
            "root_hash": root.root_hash,
            "entry_count": root.entry_count,
            "sealed_at": root.sealed_at,
        }
        try:
            return bool(
                self._verify_object(signable, root.signature_b64, root.signer_public_key_b64)
            )
        except Exception as exc:
            logger.warning("Root signature verification raised: %s", exc)
            return False
