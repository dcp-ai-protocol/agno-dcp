# Quickstart

This page mirrors the example in the README in a slightly more
verbose form, with each step explained.

## Install

```bash
pip install agno-dcp
```

For Postgres-backed storage:

```bash
pip install "agno-dcp[postgres]"
```

`agno` itself is a peer dependency; install your preferred version
separately. Python 3.11 or newer is required.

## Author a policy

Save the following as `policies.yaml`. The file is a strict subset of
YAML; both `version` and `default` are required.

```yaml
version: "1.0"
default: deny
rules:
  - name: "Allow CRM lookups"
    when:
      action_type: tool_call
      tool_name: crm_lookup
    then: allow

  - name: "Limit payment discounts"
    when:
      action_type: tool_call
      tool_name: payment_plan_offer
      payload.discount_pct:
        gt: 20
    then: deny
    reason: "Discounts above 20% require human approval"
```

The matcher supports dotted paths (`payload.discount_pct`) and the
operators `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `nin`. The first
matching rule wins. If no rule matches, the `default` verdict
applies.

## Wire up an agent

```python
import asyncio
from agno_dcp import (
    DCPAgent,
    PolicyEngine,
    MerkleAuditChain,
    SQLiteStorage,
)


async def main() -> None:
    storage = SQLiteStorage("./agent.db")
    audit = MerkleAuditChain(storage=storage)
    policy = PolicyEngine.from_yaml("policies.yaml")

    agent = DCPAgent(
        # Native Agno arguments
        name="Collections Agent",
        # ... model, tools, instructions ...

        # DCP-AI governance arguments
        dcp_human_principal="ops@example.com",
        dcp_security_tier="tier-3",
        dcp_audit_chain=audit,
        dcp_policy_engine=policy,
        dcp_strict_mode=True,
    )
    await agent.dcp_initialize()

    def crm_lookup(customer_id: int) -> dict:
        return {"id": customer_id, "name": "Acme Co."}

    result = await agent.run_tool(crm_lookup, {"customer_id": 1234})
    print(result)


asyncio.run(main())
```

`run_tool` performs the full DCP-AI sequence:

1. Build and sign an :class:`IntentDeclaration` with the agent's
   keypair.
2. Forward the intent to the :class:`PolicyGate`, which verifies the
   signature, evaluates the engine, and persists both records.
3. If the verdict is deny and `dcp_strict_mode=True`, raise
   :class:`PolicyDenied`. Otherwise execute the tool.
4. Append a `TOOL_EXECUTED` (or `ERROR`) audit event.
5. Return the tool's result.

## Seal a Merkle root

Periodically (end of session, every N minutes, before a deploy) seal
the audit chain root:

```python
root = await audit.seal_root()
print(root.root_hash, root.entry_count, root.signature_b64[:16])
```

The signed root is persisted in `dcp_audit_roots`. Auditors verify it
later with the bundled CLI:

```bash
agno-dcp verify --sqlite ./agent.db
```

## Production deployment

Swap `SQLiteStorage` for `PostgresStorage` and the rest of the code
stays identical:

```python
from agno_dcp import PostgresStorage  # requires the [postgres] extra

storage = PostgresStorage("postgresql+psycopg://user:pass@host/db")
await storage.initialize()
audit = MerkleAuditChain(storage=storage)
```

The Postgres schema is bundled at
`agno_dcp/storage/schema.sql`. `initialize()` runs it idempotently;
re-running against an existing database is a no-op.
