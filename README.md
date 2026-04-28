# agno-dcp

[![PyPI](https://img.shields.io/pypi/v/agno-dcp.svg)](https://pypi.org/project/agno-dcp/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/dcp-ai-protocol/agno-dcp/actions/workflows/ci.yml/badge.svg)](https://github.com/dcp-ai-protocol/agno-dcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/agno-dcp.svg)](https://pypi.org/project/agno-dcp/)

**Cryptographic governance for [Agno](https://www.agno.com/) agents. Identity, policy gates, and tamper-evident audit trails for production agentic systems.**

`agno-dcp` is an opt-in governance layer that wraps Agno's `Agent`, `Team`, `Workflow`, and MCP primitives with the [Digital Citizenship Protocol for AI Agents (DCP-AI)](https://dcp-ai.org/). The library does not modify Agno; you import `DCPAgent` instead of `Agent`, pass two extra arguments, and gain:

* a tamper-evident **Citizenship Bundle** for every agent (DCP-01)
* a signed **Intent Declaration** plus signed **Policy Decision** for every action (DCP-02)
* a hash-chained, Merkle-sealed **audit trail** that any external auditor can verify offline (DCP-03)
* signed **inter-agent (MCP) messages** for cross-organisation trust (DCP-04)

If DCP-AI is not active, the agent runs identically to a plain Agno agent.

---

## Why agno-dcp

Agno gives you the runtime. `agno-dcp` gives you the paper trail regulated buyers ask for before signing.

| Capability                       | Agno alone           | Agno + agno-dcp                                    |
| -------------------------------- | -------------------- | -------------------------------------------------- |
| Cryptographic agent identity     | Not provided         | Self-signed Citizenship Bundle (Ed25519)           |
| Policy enforcement               | Programmatic guards  | Declarative YAML rules, signed allow/deny verdicts |
| Audit integrity                  | Standard logs        | Hash-chained, Merkle-sealed, offline-verifiable    |
| Inter-agent trust                | JWT / app-level      | DCP-04 envelope: signed MCP messages               |
| Compliance ready (EU AI Act)     | Bring your own       | Articles 12, 13, 14, 15, 50 mapped out of the box  |
| Compliance ready (NIST AI RMF)   | Bring your own       | Govern, Map, Measure, Manage mappings included     |
| Post-quantum readiness           | Not addressed        | Ed25519 + ML-DSA-65 hybrid via DCP-AI v2.0         |

For a longer pitch see [docs/why.md](docs/why.md).

---

## Installation

```bash
pip install agno-dcp
```

For the production Postgres backend:

```bash
pip install "agno-dcp[postgres]"
```

Requires Python 3.11 or newer. Agno is a peer dependency: install your preferred Agno version separately.

---

## Quickstart

```python
import asyncio

from agno_dcp import (
    DCPAgent,
    PolicyEngine,
    MerkleAuditChain,
    SQLiteStorage,
)


async def main() -> None:
    # 1. Storage and audit chain
    storage = SQLiteStorage("./agent.db")
    audit = MerkleAuditChain(storage=storage)

    # 2. Policy engine from a YAML file
    policy = PolicyEngine.from_yaml("policies.yaml")

    # 3. Wrap an Agno Agent
    agent = DCPAgent(
        # Native Agno arguments (forwarded as-is)
        name="Collections Agent",
        model="claude:sonnet-4",
        tools=[crm_lookup, payment_plan_offer],
        instructions="You help customers reschedule overdue invoices.",
        # DCP-AI governance arguments
        dcp_human_principal="ops@example.com",
        dcp_security_tier="tier-3",
        dcp_audit_chain=audit,
        dcp_policy_engine=policy,
        dcp_strict_mode=True,
    )
    await agent.dcp_initialize()

    # 4. Run a tool through the full DCP-AI pipeline
    result = await agent.run_tool(
        crm_lookup,
        {"customer_id": 12345},
    )

    # 5. Periodically seal a tamper-evident root signature
    root = await audit.seal_root()
    print(f"Sealed Merkle root: {root.root_hash}, entries: {root.entry_count}")


asyncio.run(main())
```

The corresponding `policies.yaml`:

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

---

## How it works

```
+------------------------------------------------------------+
|  Your application                                          |
|  (FastAPI, CLI, scheduled job, ...)                        |
+------------------------------------------------------------+
                |
                v
+------------------------------------------------------------+
|  DCPAgent  =  Agno Agent  +  governance hooks              |
|                                                            |
|     pre_tool_call:  build + sign IntentDeclaration         |
|                     PolicyGate.evaluate -> PolicyDecision  |
|                     (deny -> raise PolicyDenied in strict) |
|     run tool                                               |
|     post_tool_call: append TOOL_EXECUTED audit event       |
+------------------------------------------------------------+
                |               |
                v               v
       PolicyEngine        MerkleAuditChain
       (YAML rules)        (hash-chained)
                                |
                                v
                           Storage
                  (SQLiteStorage / PostgresStorage)
                                |
                                v
                  AuditChainVerifier  (offline)
                  ComplianceBundleExporter
                  (signed ZIP for auditors)
```

The full architecture is documented in [docs/architecture.md](docs/architecture.md).

---

## Compliance mapping

* **EU AI Act**: Articles 12, 13, 14, 15, and 50 are mapped to specific DCP-AI artefacts. See [docs/compliance_mapping.md](docs/compliance_mapping.md).
* **NIST AI RMF**: Govern, Map, Measure, and Manage functions each have at least two mapped subcategories.

The library ships a one-call exporter that produces a signed ZIP archive an auditor can verify offline:

```python
from agno_dcp import ComplianceBundleExporter
from pathlib import Path

exporter = ComplianceBundleExporter(audit, storage)
bundle_path = await exporter.export(
    framework="eu_ai_act",
    output_dir=Path("./bundles"),
)
```

---

## Verifying an audit chain offline

```bash
agno-dcp verify --sqlite ./agent.db
agno-dcp verify --postgres-url $DATABASE_URL --agent-id agent:abc123 --range 0:1000
```

Recomputes every entry hash, walks the `prev_hash` linkage, and verifies the embedded signature on every sealed root. Exits non-zero on corruption.

---

## Status

`v0.1.0` is an **early access** release. The public API surface listed in [`agno_dcp/__init__.py`](agno_dcp/__init__.py) is the contract; everything else is internal and may change. Not yet recommended for production deployments handling regulated data; suitable for evaluation, demo work, and internal pilots.

What ships today (DCP-01 through DCP-04):

* Citizenship Bundle generation, loading, verification.
* Declarative YAML policy engine with signed verdicts.
* Hash-chained, Merkle-sealed audit log on SQLite or Postgres.
* MCP envelope signing and verification.
* `agno-dcp verify` CLI for offline integrity checks.
* Compliance Bundle exporter (EU AI Act + NIST AI RMF mappings).

What is **not** in `v0.1.0`:

* End-to-end demo (planned for `v0.2.0`).
* External HTTP policy engine.
* DCP-05 through DCP-09 (lifecycle, succession, dispute, rights, delegation).
* UI or dashboard.
* MongoDB and other non-SQL backends.
* Hardware-backed key custody (AWS KMS, GCP Cloud KMS).

A production-ready demo is on the roadmap for Q2 2026.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The project follows the same conventions as [DCP-AI](https://github.com/dcp-ai-protocol/dcp-ai): Conventional Commits, Apache 2.0, ruff for formatting, mypy strict for typing.

---

## License and acknowledgments

Apache 2.0. See [LICENSE](LICENSE).

`agno-dcp` is built on top of:

* [Agno](https://www.agno.com/) for the agent runtime.
* [DCP-AI](https://dcp-ai.org/) for the protocol and crypto primitives.
* [Pydantic 2](https://docs.pydantic.dev/), [SQLAlchemy 2](https://www.sqlalchemy.org/), and [PyYAML](https://pyyaml.org/) for the data plane.
