"""Compliance framework mappings.

Each module exports a single dict that maps DCP-AI capabilities to
specific articles, controls, or functions of an external compliance
framework. The mappings are deliberately verbose and human readable
so they can be inspected by an auditor without reading source code.
"""

from agno_dcp.compliance.eu_ai_act import EU_AI_ACT_MAPPING, eu_ai_act_report
from agno_dcp.compliance.nist_ai_rmf import NIST_AI_RMF_MAPPING, nist_ai_rmf_report

__all__ = [
    "EU_AI_ACT_MAPPING",
    "NIST_AI_RMF_MAPPING",
    "eu_ai_act_report",
    "nist_ai_rmf_report",
]
