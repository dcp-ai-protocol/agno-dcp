"""Tests for agno_dcp.agent.DCPAgent."""

from __future__ import annotations

from typing import Any

import pytest

from agno_dcp import (
    ConfigurationError,
    DCPAgent,
    PolicyDenied,
    PolicyEngine,
    RuleSet,
)


def test_dcpagent_requires_human_principal() -> None:
    with pytest.raises(ConfigurationError):
        DCPAgent(dcp_human_principal="")


def test_dcpagent_requires_pubkey_when_existing_bundle_provided() -> None:
    from agno_dcp.identity import generate_citizenship_bundle

    bundle, _secret = generate_citizenship_bundle(agent_name="X", human_principal="x@y.com")
    with pytest.raises(ConfigurationError):
        DCPAgent(
            dcp_human_principal="x@y.com",
            dcp_existing_bundle=bundle,
        )


@pytest.mark.asyncio
async def test_dcpagent_construct_and_initialize() -> None:
    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        dcp_security_tier="tier-2",
        name="Test Agent",
    )
    assert agent.dcp_bundle.agent_name == "Test Agent"
    assert agent.dcp_bundle.security_tier == "tier-2"
    await agent.dcp_initialize()

    # Re-init is a no-op
    await agent.dcp_initialize()

    # AGENT_CREATED audit event recorded
    entries = await agent.dcp_audit_chain.storage.get_audit_entries()
    assert any(e["event_type"] == "AGENT_CREATED" for e in entries)


@pytest.mark.asyncio
async def test_dcpagent_run_tool_async() -> None:
    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        name="Async Tool Test",
    )

    async def my_async_tool(x: int) -> int:
        return x * 2

    result = await agent.run_tool(my_async_tool, {"x": 21})
    assert result == 42

    entries = await agent.dcp_audit_chain.storage.get_audit_entries()
    types = [e["event_type"] for e in entries]
    assert "INTENT_DECLARED" in types
    assert "POLICY_DECISION" in types
    assert "TOOL_EXECUTED" in types


@pytest.mark.asyncio
async def test_dcpagent_run_tool_sync() -> None:
    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        name="Sync Tool Test",
    )

    def my_sync_tool(x: int) -> int:
        return x + 1

    result = await agent.run_tool(my_sync_tool, {"x": 41}, tool_name="adder")
    assert result == 42


@pytest.mark.asyncio
async def test_dcpagent_strict_mode_blocks_unknown_tool() -> None:
    rules = RuleSet.from_dict(
        {
            "version": "1.0",
            "default": "deny",
            "rules": [],
        }
    )
    engine = PolicyEngine(rules)
    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        dcp_policy_engine=engine,
        dcp_strict_mode=True,
        name="Strict",
    )

    def some_tool() -> int:
        return 1

    with pytest.raises(PolicyDenied):
        await agent.run_tool(some_tool, {})


@pytest.mark.asyncio
async def test_dcpagent_observation_mode_records_deny_but_runs() -> None:
    rules = RuleSet.from_dict({"version": "1.0", "default": "deny", "rules": []})
    engine = PolicyEngine(rules)
    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        dcp_policy_engine=engine,
        dcp_strict_mode=False,
        name="Observation",
    )

    def some_tool() -> int:
        return 7

    result = await agent.run_tool(some_tool, {}, tool_name="some_tool")
    assert result == 7

    entries = await agent.dcp_audit_chain.storage.get_audit_entries()
    decisions = [e for e in entries if e["event_type"] == "POLICY_DECISION"]
    assert any(d["payload"]["approved"] is False for d in decisions)


@pytest.mark.asyncio
async def test_dcpagent_tool_error_is_audited() -> None:
    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        name="ErrorAudit",
    )

    def failing_tool() -> Any:
        raise ValueError("intentional")

    with pytest.raises(ValueError):
        await agent.run_tool(failing_tool, {})

    entries = await agent.dcp_audit_chain.storage.get_audit_entries()
    err_entries = [e for e in entries if e["event_type"] == "ERROR"]
    assert len(err_entries) >= 1
    assert any("intentional" in e["payload"]["error_message"] for e in err_entries)


@pytest.mark.asyncio
async def test_dcpagent_pre_post_hooks_directly() -> None:
    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        name="HookDirect",
    )
    decision = await agent.dcp_pre_tool_call("crm_lookup", {"customer_id": 1})
    assert decision.approved is True

    await agent.dcp_post_tool_call("crm_lookup", {"customer_id": 1}, result={"name": "test"})
