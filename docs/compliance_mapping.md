# Compliance mapping

`agno-dcp` ships two structured mappings: EU AI Act and NIST AI RMF.
Both are exposed as Python data so they can be embedded in compliance
bundles, rendered to PDF, or fed to a documentation generator.

## EU AI Act

Module: `agno_dcp.compliance.eu_ai_act`

Articles covered:

| Article    | Title                                                  | DCP-AI capability                                                   |
| ---------- | ------------------------------------------------------ | ------------------------------------------------------------------- |
| Article 12 | Record-keeping                                         | DCP-03 hash-chained audit trail; offline verifier; sealed roots.    |
| Article 13 | Transparency to deployers                              | DCP-02 Intent + Policy Decision recorded for every gated action.   |
| Article 14 | Human oversight                                        | DCP-01 dcp_human_principal binding; strict-mode deny halts action. |
| Article 15 | Accuracy, robustness, cybersecurity                    | DCP-AI v2.0 hybrid PQ signatures; AES-256-GCM A2A sessions.        |
| Article 50 | Transparency obligations to natural persons            | Citizenship Bundle is publishable; MCP envelope advertises identity. |

```python
from agno_dcp.compliance import EU_AI_ACT_MAPPING, eu_ai_act_report

report = eu_ai_act_report(
    audit_summary={
        "agents": 3,
        "entries_checked": 1842,
        "chain_intact": True,
    }
)
```

## NIST AI RMF

Module: `agno_dcp.compliance.nist_ai_rmf`

Functions covered:

| Function | Subcategories | DCP-AI capability                                                 |
| -------- | ------------- | ----------------------------------------------------------------- |
| GOVERN   | 1.4, 4.2      | PolicyEngine declarative ruleset; dcp_human_principal accountability. |
| MAP      | 2.3, 4.1      | Audit chain enables retrospective TEVV; SecurityTier risk classification. |
| MEASURE  | 2.7, 2.8      | Hybrid PQ signatures; AES-256-GCM A2A; Compliance Bundle exporter. |
| MANAGE   | 1.3, 4.1      | Conditional rules; periodic Merkle root seals; offline verifier.  |

```python
from agno_dcp.compliance import NIST_AI_RMF_MAPPING, nist_ai_rmf_report

report = nist_ai_rmf_report(audit_summary={"chain_intact": True})
```

## Compliance Bundle exporter

Both mappings are embedded in the signed ZIP archives produced by
:class:`agno_dcp.audit.ComplianceBundleExporter`:

```python
from pathlib import Path
from agno_dcp import ComplianceBundleExporter

exporter = ComplianceBundleExporter(audit_chain, storage)
zip_path = await exporter.export(
    framework="eu_ai_act",   # or "nist_ai_rmf"
    output_dir=Path("./bundles"),
    agent_id=None,           # all agents
)
```

The archive contains:

* `manifest.json` - bundle metadata + signature.
* `compliance_mapping.json` - the framework mapping.
* `audit_log.jsonl` - all audit entries in index order.
* `roots.jsonl` - signed Merkle root snapshots.
* `citizenship_bundles/<agent_id>.json` - one file per agent.

## Disclaimer

These mappings are informative, not legal advice. Consult counsel or
your compliance team before relying on them for regulatory
submissions or assurance engagements.
