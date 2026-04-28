"""DCP-AI capabilities mapped to NIST AI RMF (NIST AI 100-1) functions.

NIST AI RMF organises practice into four core functions: Govern, Map,
Measure, and Manage. Each function decomposes into categories and
subcategories. The mapping below highlights subcategories where
DCP-AI provides a direct technical artifact.
"""

from __future__ import annotations

from typing import Any

NIST_AI_RMF_MAPPING: dict[str, Any] = {
    "framework": "NIST AI Risk Management Framework",
    "version": "AI RMF 1.0 (NIST AI 100-1, January 2023)",
    "functions": [
        {
            "function": "GOVERN",
            "categories": [
                {
                    "id": "GOVERN 1.4",
                    "subject": "Risk management process is established",
                    "dcp_ai_capability": [
                        "agno_dcp.policy.PolicyEngine: declarative ruleset "
                        "with default-deny posture and named rules",
                        "agno_dcp.policy.PolicyGate: every action passes "
                        "through a signed allow/deny verdict",
                    ],
                },
                {
                    "id": "GOVERN 4.2",
                    "subject": "Personnel are accountable for the AI system",
                    "dcp_ai_capability": [
                        "DCP-01: dcp_human_principal binds every agent to "
                        "a named accountable human",
                        "agno_dcp.identity.CitizenshipBundle is tamper-evident",
                    ],
                },
            ],
        },
        {
            "function": "MAP",
            "categories": [
                {
                    "id": "MAP 2.3",
                    "subject": "Scientific integrity and TEVV considerations",
                    "dcp_ai_capability": [
                        "DCP-03: hash-chained audit log enables retrospective "
                        "TEVV (test, evaluation, verification, validation) "
                        "without trusting the live system",
                        "agno_dcp.audit.AuditChainVerifier produces an offline integrity report",
                    ],
                },
                {
                    "id": "MAP 4.1",
                    "subject": "Approaches for mapping AI risks",
                    "dcp_ai_capability": [
                        "agno_dcp.identity.SecurityTier (tier-1..tier-4) "
                        "encodes risk classification per agent",
                        "PolicyEngine rules can branch on agent_security_tier and payload values",
                    ],
                },
            ],
        },
        {
            "function": "MEASURE",
            "categories": [
                {
                    "id": "MEASURE 2.7",
                    "subject": "AI system security and resilience",
                    "dcp_ai_capability": [
                        "DCP-AI v2.0: hybrid post-quantum signatures (Ed25519 + ML-DSA-65)",
                        "DCP-04: AES-256-GCM session encryption for agent-to-agent communication",
                    ],
                },
                {
                    "id": "MEASURE 2.8",
                    "subject": "AI system transparency and accountability",
                    "dcp_ai_capability": [
                        "DCP-02 + DCP-03: every action has a signed intent, "
                        "a signed decision, and a chained audit entry",
                        "agno_dcp.audit.ComplianceBundleExporter: signed ZIP for external auditors",
                    ],
                },
            ],
        },
        {
            "function": "MANAGE",
            "categories": [
                {
                    "id": "MANAGE 1.3",
                    "subject": "Risk treatment plans are developed",
                    "dcp_ai_capability": [
                        "agno_dcp.policy: rules can deny actions outright "
                        "or attach conditions for human review",
                        "agno_dcp.exceptions.PolicyDenied surfaces a "
                        "structured deny payload to handlers",
                    ],
                },
                {
                    "id": "MANAGE 4.1",
                    "subject": "Post-deployment monitoring",
                    "dcp_ai_capability": [
                        "agno_dcp.audit.MerkleAuditChain.seal_root produces "
                        "a periodic tamper-evident checkpoint",
                        "agno_dcp.audit.AuditChainVerifier runs entirely "
                        "offline against persisted state",
                    ],
                },
            ],
        },
    ],
}


def nist_ai_rmf_report(audit_summary: dict[str, Any]) -> dict[str, Any]:
    """Build a human-readable mapping report for NIST AI RMF.

    Same structure as :func:`eu_ai_act_report`.
    """
    return {
        "framework": NIST_AI_RMF_MAPPING["framework"],
        "version": NIST_AI_RMF_MAPPING["version"],
        "audit_summary": audit_summary,
        "functions": NIST_AI_RMF_MAPPING["functions"],
        "disclaimer": (
            "This mapping is informative. It does not constitute legal "
            "advice. Consult your compliance team before relying on "
            "this mapping for regulatory or assurance submissions."
        ),
    }


__all__ = ["NIST_AI_RMF_MAPPING", "nist_ai_rmf_report"]
