"""Policy gating layer (DCP-02) for agno-dcp.

Public surface:

* :class:`IntentDeclaration`: the signed intent an agent emits before
  every gated action.
* :class:`PolicyDecision`: the signed allow / deny outcome.
* :class:`PolicyGate`: stitches an intent through an engine, persists
  both, and surfaces a typed decision.
* :class:`PolicyEngine`: rule evaluator. Built-in YAML loader; the
  HTTP / external loader is reserved for v0.2.0.
"""

from agno_dcp.policy.engine import PolicyEngine
from agno_dcp.policy.gate import IntentDeclaration, PolicyDecision, PolicyGate
from agno_dcp.policy.rules import RuleSet

__all__ = [
    "IntentDeclaration",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyGate",
    "RuleSet",
]
