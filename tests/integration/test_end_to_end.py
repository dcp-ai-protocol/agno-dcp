"""End-to-end test: agent + policy + audit + verifier + exporter.

Exercises the full DCP-AI surface in one flow without requiring
``agno`` to be installed (DCPAgent's stub parent permits this).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agno_dcp import (
    AuditChainVerifier,
    ComplianceBundleExporter,
    DCPAgent,
    MerkleAuditChain,
    PolicyEngine,
    RuleSet,
    SQLiteStorage,
)


@pytest.mark.asyncio
async def test_full_flow_observation(tmp_path: Path) -> None:
    storage = SQLiteStorage(":memory:")
    await storage.initialize()
    audit = MerkleAuditChain(storage=storage)

    rules = RuleSet.from_dict(
        {
            "version": "1.0",
            "default": "deny",
            "rules": [
                {
                    "name": "Allow lookups",
                    "when": {"action_type": "tool_call", "tool_name": "crm_lookup"},
                    "then": "allow",
                }
            ],
        }
    )
    engine = PolicyEngine(rules)

    agent = DCPAgent(
        dcp_human_principal="ops@example.com",
        dcp_audit_chain=audit,
        dcp_policy_engine=engine,
        dcp_strict_mode=False,
        name="EndToEnd",
    )
    await agent.dcp_initialize()

    # Approved tool
    def crm_lookup(customer_id: int) -> dict[str, str]:
        return {"id": str(customer_id), "name": "Acme"}

    result = await agent.run_tool(crm_lookup, {"customer_id": 99})
    assert result["name"] == "Acme"

    # Denied tool (in observation mode it still runs and is logged)
    def send_email(to: str, body: str) -> str:
        return "sent"

    await agent.run_tool(send_email, {"to": "x@example.com", "body": "hi"})

    # Seal a root and verify integrity
    root = await audit.seal_root()
    assert root.entry_count > 0

    verifier = AuditChainVerifier(storage)
    res = await verifier.verify()
    assert res.chain_intact is True
    assert res.entries_corrupted == []

    # Export a compliance bundle and check the file exists
    exporter = ComplianceBundleExporter(audit, storage)
    bundle_path = await exporter.export(
        framework="eu_ai_act",
        output_dir=tmp_path / "bundles",
        agent_id=agent.dcp_bundle.agent_id,
    )
    assert bundle_path.exists()
    assert bundle_path.suffix == ".zip"
    assert bundle_path.stat().st_size > 0

    await storage.close()
