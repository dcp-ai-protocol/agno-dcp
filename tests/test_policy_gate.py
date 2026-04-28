"""Tests for agno_dcp.policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from agno_dcp import (
    ConfigurationError,
    IntentDeclaration,
    MerkleAuditChain,
    PolicyDecision,
    PolicyDenied,
    PolicyEngine,
    PolicyGate,
    RuleSet,
)
from agno_dcp.policy.rules import _matches  # type: ignore[attr-defined]


def test_ruleset_matcher_equality() -> None:
    rule_when = {"action_type": "tool_call", "tool_name": "crm_lookup"}
    assert _matches(rule_when, {"action_type": "tool_call", "tool_name": "crm_lookup"})
    assert not _matches(rule_when, {"action_type": "tool_call", "tool_name": "x"})


def test_ruleset_matcher_dotted_path() -> None:
    rule_when = {"payload.discount_pct": {"gt": 20}}
    assert _matches(rule_when, {"payload": {"discount_pct": 50}})
    assert not _matches(rule_when, {"payload": {"discount_pct": 10}})
    # missing path is a non-match, not an error
    assert not _matches(rule_when, {"payload": {}})


def test_ruleset_matcher_in_operator() -> None:
    rule_when = {"agent_security_tier": {"in": ["tier-3", "tier-4"]}}
    assert _matches(rule_when, {"agent_security_tier": "tier-3"})
    assert not _matches(rule_when, {"agent_security_tier": "tier-1"})


def test_ruleset_loads_from_yaml(tmp_policy_yaml: Path) -> None:
    rs = RuleSet.from_yaml(tmp_policy_yaml)
    assert rs.default == "deny"
    assert len(rs.rules) == 1
    assert rs.rules[0].name == "Allow CRM lookups"


def test_ruleset_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        RuleSet.from_yaml(tmp_path / "missing.yaml")


def test_ruleset_invalid_schema_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("rules: 'not a list'\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        RuleSet.from_yaml(p)


def test_ruleset_evaluate_default() -> None:
    rs = RuleSet(version="1.0", default="deny", rules=[])
    verdict, reason, rule = rs.evaluate({"action_type": "tool_call"})
    assert verdict == "deny"
    assert "default" in reason
    assert rule is None


def test_ruleset_evaluate_first_match_wins() -> None:
    rs = RuleSet.from_dict(
        {
            "version": "1.0",
            "default": "allow",
            "rules": [
                {
                    "name": "deny payment_plan_offer >20",
                    "when": {
                        "tool_name": "payment_plan_offer",
                        "payload.discount_pct": {"gt": 20},
                    },
                    "then": "deny",
                    "reason": "high discount",
                }
            ],
        }
    )
    verdict, reason, _ = rs.evaluate(
        {"tool_name": "payment_plan_offer", "payload": {"discount_pct": 50}}
    )
    assert verdict == "deny"
    assert reason == "high discount"


def test_ruleset_permissive() -> None:
    rs = RuleSet.permissive()
    assert rs.default == "allow"
    verdict, _, _ = rs.evaluate({"tool_name": "anything"})
    assert verdict == "allow"


@pytest.mark.asyncio
async def test_policy_gate_approves_simple_intent(
    policy_gate: PolicyGate, audit_chain: MerkleAuditChain
) -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    intent = IntentDeclaration.create(
        agent_id="agent:test",
        action_type="tool_call",
        action_payload={"tool_name": "anything"},
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
    )
    decision = await policy_gate.evaluate(intent)
    assert isinstance(decision, PolicyDecision)
    assert decision.approved is True
    # Storage should have recorded the intent and decision.
    entries = await audit_chain.storage.get_audit_entries()
    types = [e["event_type"] for e in entries]
    assert "INTENT_DECLARED" in types
    assert "POLICY_DECISION" in types


@pytest.mark.asyncio
async def test_policy_gate_strict_mode_raises_on_deny(
    deny_unknown_tools_engine: PolicyEngine,
    audit_chain: MerkleAuditChain,
) -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    gate = PolicyGate(engine=deny_unknown_tools_engine, audit_chain=audit_chain, strict=True)
    intent = IntentDeclaration.create(
        agent_id="agent:strict",
        action_type="tool_call",
        action_payload={"tool_name": "totally_unknown_tool"},
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
    )
    with pytest.raises(PolicyDenied) as excinfo:
        await gate.evaluate(intent)
    assert excinfo.value.intent is intent
    assert excinfo.value.decision is not None


@pytest.mark.asyncio
async def test_policy_gate_observation_mode_returns_deny(
    deny_unknown_tools_engine: PolicyEngine,
    audit_chain: MerkleAuditChain,
) -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    gate = PolicyGate(engine=deny_unknown_tools_engine, audit_chain=audit_chain, strict=False)
    intent = IntentDeclaration.create(
        agent_id="agent:obs",
        action_type="tool_call",
        action_payload={"tool_name": "totally_unknown_tool"},
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
    )
    decision = await gate.evaluate(intent)
    assert decision.approved is False


@pytest.mark.asyncio
async def test_policy_gate_invalid_intent_signature(
    policy_gate: PolicyGate,
) -> None:
    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    intent = IntentDeclaration.create(
        agent_id="agent:bad-sig",
        action_type="tool_call",
        action_payload={"tool_name": "anything"},
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
    )
    intent.action_payload["mutated"] = True
    decision = await policy_gate.evaluate(intent)
    assert decision.approved is False
    assert "signature" in decision.reason.lower()


def test_policy_engine_from_external_raises() -> None:
    with pytest.raises(NotImplementedError):
        PolicyEngine.from_external("https://example.com/policy")


def test_policy_engine_verify_decision_roundtrip(
    deny_unknown_tools_engine: PolicyEngine,
) -> None:
    import asyncio

    from dcp_ai.crypto import generate_keypair  # type: ignore[import-not-found]

    kp = generate_keypair()
    intent = IntentDeclaration.create(
        agent_id="agent:vfy",
        action_type="tool_call",
        action_payload={"tool_name": "crm_lookup"},
        secret_key_b64=kp["secret_key_b64"],
        public_key_b64=kp["public_key_b64"],
    )
    decision = asyncio.run(deny_unknown_tools_engine.evaluate(intent))
    assert deny_unknown_tools_engine.verify_decision(decision) is True
    decision.reason = "tampered"
    assert deny_unknown_tools_engine.verify_decision(decision) is False
