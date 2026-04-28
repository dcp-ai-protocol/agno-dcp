"""Tests for agno_dcp.audit.chain.MerkleAuditChain."""

from __future__ import annotations

import pytest

from agno_dcp import (
    AuditChainCorrupted,
    AuditEvent,
    AuditEventType,
    MerkleAuditChain,
    SQLiteStorage,
)


@pytest.mark.asyncio
async def test_append_assigns_monotonic_index(audit_chain: MerkleAuditChain) -> None:
    e1 = await audit_chain.append(
        AuditEvent(
            event_type=AuditEventType.AGENT_CREATED,
            agent_id="agent:a",
            payload={"k": 1},
        )
    )
    e2 = await audit_chain.append(
        AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTED,
            agent_id="agent:a",
            payload={"k": 2},
        )
    )
    assert e1.entry_index < e2.entry_index
    assert e1.prev_hash == "GENESIS"
    assert e2.prev_hash == e1.entry_hash


@pytest.mark.asyncio
async def test_chain_links_correctly(audit_chain: MerkleAuditChain) -> None:
    for i in range(5):
        await audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTED,
                agent_id="agent:b",
                payload={"i": i},
            )
        )
    ok = await audit_chain.verify_range(start=0)
    assert ok is True


@pytest.mark.asyncio
async def test_seal_root_signs_state(audit_chain: MerkleAuditChain) -> None:
    for i in range(3):
        await audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTED,
                agent_id="agent:c",
                payload={"i": i},
            )
        )
    root = await audit_chain.seal_root()
    assert root.entry_count == 3
    assert root.root_hash != "GENESIS"
    assert root.signature_b64
    assert await audit_chain.verify_root_signature(root) is True


@pytest.mark.asyncio
async def test_seal_root_empty_chain(audit_chain: MerkleAuditChain) -> None:
    root = await audit_chain.seal_root()
    assert root.entry_count == 0
    assert root.root_hash == "GENESIS"
    assert await audit_chain.verify_root_signature(root) is True


@pytest.mark.asyncio
async def test_corrupted_chain_is_detected(storage: SQLiteStorage) -> None:
    chain = MerkleAuditChain(storage=storage)
    for i in range(3):
        await chain.append(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTED,
                agent_id="agent:d",
                payload={"i": i},
            )
        )
    # Tamper directly with the underlying row.
    conn = storage._connect()  # type: ignore[attr-defined]
    conn.execute(
        "UPDATE dcp_audit_chain SET payload = ? WHERE entry_index = 2",
        ('{"i": 999}',),
    )
    with pytest.raises(AuditChainCorrupted) as excinfo:
        await chain.verify_range(start=0)
    assert excinfo.value.entry_index == 2


@pytest.mark.asyncio
async def test_verify_root_signature_rejects_tampered_root(
    audit_chain: MerkleAuditChain,
) -> None:
    await audit_chain.append(
        AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTED,
            agent_id="agent:e",
            payload={"x": 1},
        )
    )
    root = await audit_chain.seal_root()
    root.entry_count = 999
    assert await audit_chain.verify_root_signature(root) is False


@pytest.mark.asyncio
async def test_chain_uses_provided_signing_key(storage: SQLiteStorage) -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    chain = MerkleAuditChain(
        storage=storage,
        signer_secret_key_b64=kp["secret_key_b64"],
        signer_public_key_b64=kp["public_key_b64"],
    )
    assert chain.signer_public_key_b64 == kp["public_key_b64"]


@pytest.mark.asyncio
async def test_chain_requires_pubkey_with_secret(storage: SQLiteStorage) -> None:
    from agno_dcp.exceptions import IdentityError

    with pytest.raises(IdentityError):
        MerkleAuditChain(
            storage=storage,
            signer_secret_key_b64="abc",
            signer_public_key_b64=None,
        )
