"""Shared pytest fixtures.

Tests do not require ``agno`` to be installed; the package's
lazy-import shim provides a stub. Tests do require ``dcp-ai>=2.8.1``
because the cryptographic primitives are non-mockable (we want the
tests to exercise real signatures).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from agno_dcp import (
    MerkleAuditChain,
    PolicyEngine,
    PolicyGate,
    RuleSet,
    SQLiteStorage,
)


@pytest.fixture
def event_loop_policy() -> asyncio.AbstractEventLoopPolicy:
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture
async def storage() -> AsyncIterator[SQLiteStorage]:
    """Fresh in-memory SQLite storage per test."""
    s = SQLiteStorage(":memory:")
    await s.initialize()
    try:
        yield s
    finally:
        await s.close()


@pytest_asyncio.fixture
async def audit_chain(storage: SQLiteStorage) -> AsyncIterator[MerkleAuditChain]:
    chain = MerkleAuditChain(storage=storage)
    yield chain


@pytest.fixture
def permissive_engine() -> PolicyEngine:
    return PolicyEngine.permissive()


@pytest.fixture
def deny_unknown_tools_engine() -> PolicyEngine:
    rules = RuleSet.from_dict(
        {
            "version": "1.0",
            "default": "deny",
            "rules": [
                {
                    "name": "Allow CRM lookups",
                    "when": {"action_type": "tool_call", "tool_name": "crm_lookup"},
                    "then": "allow",
                },
                {
                    "name": "Deny large discounts",
                    "when": {
                        "action_type": "tool_call",
                        "tool_name": "payment_plan_offer",
                        "payload.discount_pct": {"gt": 20},
                    },
                    "then": "deny",
                    "reason": "Discounts above 20% require human approval",
                },
            ],
        }
    )
    return PolicyEngine(rules)


@pytest_asyncio.fixture
async def policy_gate(
    permissive_engine: PolicyEngine,
    audit_chain: MerkleAuditChain,
) -> AsyncIterator[PolicyGate]:
    gate = PolicyGate(engine=permissive_engine, audit_chain=audit_chain)
    yield gate


@pytest.fixture
def tmp_policy_yaml(tmp_path: Path) -> Path:
    p = tmp_path / "policies.yaml"
    p.write_text(
        "version: '1.0'\n"
        "default: deny\n"
        "rules:\n"
        "  - name: 'Allow CRM lookups'\n"
        "    when:\n"
        "      action_type: tool_call\n"
        "      tool_name: crm_lookup\n"
        "    then: allow\n",
        encoding="utf-8",
    )
    return p
