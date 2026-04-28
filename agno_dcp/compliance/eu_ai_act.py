"""DCP-AI capabilities mapped to EU AI Act articles.

The mapping is informative, not legal advice. It expresses which
DCP-AI artifacts can support which obligation in a documented way.
The list is intentionally conservative: only obligations where DCP-AI
provides a direct technical capability are listed.
"""

from __future__ import annotations

from typing import Any

EU_AI_ACT_MAPPING: dict[str, Any] = {
    "framework": "EU AI Act (Regulation (EU) 2024/1689)",
    "version": "Final text, OJEU 2024-07-12",
    "controls": [
        {
            "article": "Article 12",
            "title": "Record-keeping",
            "obligation": (
                "High-risk AI systems shall be designed and developed "
                "with capabilities enabling the automatic recording of "
                "events ('logs') over the lifetime of the system."
            ),
            "dcp_ai_capability": [
                "DCP-03: hash-chained, dual-Merkle audit trail per agent",
                "agno_dcp.audit.MerkleAuditChain (append-only, sealed roots)",
                "agno_dcp.audit.AuditChainVerifier (offline integrity check)",
            ],
        },
        {
            "article": "Article 13",
            "title": "Transparency and provision of information to deployers",
            "obligation": (
                "High-risk AI systems shall be designed and developed "
                "in such a way to ensure that their operation is "
                "sufficiently transparent to enable deployers to "
                "interpret a system's output and use it appropriately."
            ),
            "dcp_ai_capability": [
                "DCP-02: Intent Declaration recorded before each action",
                "DCP-02: signed Policy Decision (allow/deny + reason) stored "
                "alongside every gated action",
                "agno_dcp.policy.PolicyDecision exposes engine_id, rule_name, "
                "and conditions for human review",
            ],
        },
        {
            "article": "Article 14",
            "title": "Human oversight",
            "obligation": (
                "High-risk AI systems shall be designed and developed "
                "in such a way [...] that they can be effectively "
                "overseen by natural persons during the period in which "
                "the AI system is in use."
            ),
            "dcp_ai_capability": [
                "DCP-01: Responsible Principal Binding ties every agent to "
                "a named human or organisation (dcp_human_principal)",
                "DCP-02: deny verdicts halt action in strict mode",
                "DCP-09 (out of scope for v0.1.0): formal delegation mandates "
                "and awareness thresholds",
            ],
        },
        {
            "article": "Article 15",
            "title": "Accuracy, robustness and cybersecurity",
            "obligation": (
                "High-risk AI systems shall be designed and developed "
                "in such a way that they achieve [...] an appropriate "
                "level of accuracy, robustness, and cybersecurity, and "
                "that they perform consistently in those respects "
                "throughout their lifecycle."
            ),
            "dcp_ai_capability": [
                "DCP-AI v2.0: hybrid Ed25519 + ML-DSA-65 composite "
                "signatures (post-quantum capable, NIST FIPS 203/204/205 "
                "aligned)",
                "DCP-04: AES-256-GCM session encryption for inter-agent communication",
                "agno_dcp.policy: explicit deny-by-default policy gate with signed verdicts",
            ],
        },
        {
            "article": "Article 50",
            "title": "Transparency obligations for providers and deployers",
            "obligation": (
                "Providers shall ensure that AI systems intended to "
                "interact directly with natural persons are designed "
                "and developed in such a way that the natural persons "
                "concerned are informed that they are interacting with "
                "an AI system."
            ),
            "dcp_ai_capability": [
                "DCP-01 Citizenship Bundle is publishable at a stable URL "
                "for any counterparty to inspect",
                "DCP-04 MCP envelope advertises agent identity in every "
                "outbound message (dcp_signer_public_key_b64)",
            ],
        },
    ],
}


def eu_ai_act_report(audit_summary: dict[str, Any]) -> dict[str, Any]:
    """Build a human-readable mapping report.

    Args:
        audit_summary: Free-form summary of the audited deployment.
            Typically contains entry counts, agent counts, and
            verification outcomes from
            :class:`AuditChainVerifier`.

    Returns:
        A dict suitable for embedding in a Compliance Bundle or
        rendering to PDF.
    """
    return {
        "framework": EU_AI_ACT_MAPPING["framework"],
        "version": EU_AI_ACT_MAPPING["version"],
        "audit_summary": audit_summary,
        "controls": EU_AI_ACT_MAPPING["controls"],
        "disclaimer": (
            "This mapping is informative. It does not constitute legal "
            "advice. Consult counsel before relying on this mapping for "
            "regulatory submissions."
        ),
    }


__all__ = ["EU_AI_ACT_MAPPING", "eu_ai_act_report"]
