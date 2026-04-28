"""Tests for agno_dcp.mcp.middleware."""

from __future__ import annotations

import pytest

from agno_dcp import (
    DCPMCPMiddleware,
    MCPVerificationError,
    MerkleAuditChain,
    SQLiteStorage,
    sign_mcp_message,
    verify_mcp_message,
)
from agno_dcp.mcp.middleware import has_envelope


def test_sign_then_verify_roundtrip() -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    msg = {"method": "tools/call", "params": {"name": "echo", "args": {"x": 1}}}
    signed = sign_mcp_message(msg, kp["secret_key_b64"], kp["public_key_b64"])
    assert has_envelope(signed)
    assert verify_mcp_message(signed) is True


def test_verify_returns_false_when_no_envelope() -> None:
    msg = {"method": "tools/call"}
    assert verify_mcp_message(msg) is False
    assert has_envelope(msg) is False


def test_verify_detects_tampering() -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    msg = {"method": "tools/call"}
    signed = sign_mcp_message(msg, kp["secret_key_b64"], kp["public_key_b64"])
    signed["method"] = "evil"
    assert verify_mcp_message(signed) is False


@pytest.mark.asyncio
async def test_middleware_seals_outbound_audit() -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    storage = SQLiteStorage(":memory:")
    await storage.initialize()
    chain = MerkleAuditChain(storage=storage)
    mw = DCPMCPMiddleware(
        agent_id="agent:m",
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
        audit_chain=chain,
    )
    out = await mw.sign_outbound({"method": "tools/list"})
    assert has_envelope(out)
    entries = await storage.get_audit_entries()
    assert any(e["event_type"] == "MCP_OUTBOUND" for e in entries)
    await storage.close()


@pytest.mark.asyncio
async def test_middleware_verify_inbound_passthrough_no_envelope() -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    mw = DCPMCPMiddleware(
        agent_id="agent:passthrough",
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
    )
    plain = {"method": "tools/list"}
    result = await mw.verify_inbound(plain)
    assert result == plain


@pytest.mark.asyncio
async def test_middleware_verify_inbound_strict_raises_on_invalid() -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    mw = DCPMCPMiddleware(
        agent_id="agent:strict",
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
        strict_inbound=True,
    )
    bad = sign_mcp_message({"method": "x"}, kp["secret_key_b64"], kp["public_key_b64"])
    bad["method"] = "evil"
    with pytest.raises(MCPVerificationError):
        await mw.verify_inbound(bad)


@pytest.mark.asyncio
async def test_middleware_verify_inbound_drops_invalid_in_observation() -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    mw = DCPMCPMiddleware(
        agent_id="agent:obs",
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
        strict_inbound=False,
    )
    bad = sign_mcp_message({"method": "x"}, kp["secret_key_b64"], kp["public_key_b64"])
    bad["method"] = "evil"
    result = await mw.verify_inbound(bad)
    assert result is None
