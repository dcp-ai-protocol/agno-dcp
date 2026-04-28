"""Declarative policy rules: YAML loader and matcher.

The rules format is documented in the README. A short example::

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

Matchers in ``when`` can be:

* Plain equality: ``action_type: tool_call``
* Nested via dotted paths: ``payload.discount_pct: 50``
* Comparison ops: ``{gt|gte|lt|lte|eq|ne|in|nin: <value>}``
* Combined with AND semantics across the dict (every key must match).

Multiple rules: the first matching rule wins. If no rule matches, the
``default`` action applies.
"""

from __future__ import annotations

import logging
from collections.abc import Callable as _Callable
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from agno_dcp.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


_VERDICT = Literal["allow", "deny"]


class Rule(BaseModel):
    """One rule from the policy YAML."""

    model_config = ConfigDict(extra="forbid")

    name: str
    when: dict[str, Any] = Field(default_factory=dict)
    then: _VERDICT
    reason: str = ""
    conditions: list[str] = Field(default_factory=list)


class RuleSet(BaseModel):
    """A parsed and validated policy ruleset."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    default: _VERDICT = "deny"
    rules: list[Rule] = Field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> RuleSet:
        """Load a ruleset from a YAML file.

        Raises:
            ConfigurationError: If the file is missing, malformed, or
                fails schema validation.
        """
        p = Path(path)
        if not p.exists():
            raise ConfigurationError(f"Policy file not found: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Policy YAML parse error: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigurationError("Policy YAML must be a mapping at the top level")
        try:
            return cls.model_validate(data)
        except Exception as exc:
            raise ConfigurationError(f"Policy schema validation failed: {exc}") from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleSet:
        """Construct from an in-memory dict (useful for tests)."""
        return cls.model_validate(data)

    @classmethod
    def permissive(cls) -> RuleSet:
        """A default-allow ruleset with no rules. Every intent is
        approved with reason ``allowed by permissive default``."""
        return cls(version="1.0", default="allow", rules=[])

    def evaluate(self, context: dict[str, Any]) -> tuple[_VERDICT, str, Rule | None]:
        """Evaluate ``context`` against the ruleset.

        Returns ``(verdict, reason, matched_rule)``. ``matched_rule``
        is ``None`` when the default verdict is applied.
        """
        for rule in self.rules:
            if _matches(rule.when, context):
                reason = rule.reason or f"matched rule: {rule.name}"
                return rule.then, reason, rule
        return self.default, f"default {self.default}", None


# ── matcher implementation ────────────────────────────────────────


_OP_HANDLERS: dict[str, _Callable[[Any, Any], bool]] = {
    "eq": lambda actual, expected: actual == expected,
    "ne": lambda actual, expected: actual != expected,
    "gt": lambda actual, expected: actual is not None and actual > expected,
    "gte": lambda actual, expected: actual is not None and actual >= expected,
    "lt": lambda actual, expected: actual is not None and actual < expected,
    "lte": lambda actual, expected: actual is not None and actual <= expected,
    "in": lambda actual, expected: actual in expected,
    "nin": lambda actual, expected: actual not in expected,
}


def _resolve_path(context: dict[str, Any], dotted: str) -> Any:
    """Walk a dotted path through a nested dict.

    Returns ``None`` for missing intermediate keys rather than
    raising, so a rule that references a key that is not present is
    treated as a non-match instead of an error.
    """
    parts = dotted.split(".")
    value: Any = context
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
        if value is None:
            return None
    return value


def _matches(when: dict[str, Any], context: dict[str, Any]) -> bool:
    """Return True iff every key in ``when`` matches ``context``.

    Supports dotted keys (``payload.discount_pct``) and dict-valued
    matchers (``{gt: 20}``).
    """
    for key, expected in when.items():
        actual = _resolve_path(context, key)
        if (
            isinstance(expected, dict)
            and expected
            and all(k in _OP_HANDLERS for k in expected.keys())
        ):
            for op, op_value in expected.items():
                handler = _OP_HANDLERS[op]
                try:
                    if not handler(actual, op_value):
                        return False
                except TypeError:
                    return False
        else:
            if actual != expected:
                return False
    return True
