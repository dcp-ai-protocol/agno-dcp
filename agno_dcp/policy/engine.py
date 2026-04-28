"""Policy engine: evaluates intents against a :class:`RuleSet`.

The default engine is embedded: rules are loaded from a YAML file
and evaluated in-process. It signs every decision with its own
keypair so the audit chain can prove which engine produced which
verdict.

The HTTP / external engine variant is reserved for v0.2.0; calling
:meth:`PolicyEngine.from_external` raises :class:`NotImplementedError`
with a clear message.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agno_dcp.exceptions import ConfigurationError, IdentityError
from agno_dcp.policy.rules import RuleSet

if TYPE_CHECKING:
    from agno_dcp.policy.gate import IntentDeclaration, PolicyDecision


logger = logging.getLogger(__name__)


def _import_dcp_crypto() -> tuple[Any, Any, Any]:
    try:
        from dcp_ai.crypto import (
            generate_keypair,
            sign_object,
            verify_object,
        )
    except ImportError as exc:  # pragma: no cover
        raise IdentityError(
            "dcp_ai SDK is required for policy operations. "
            "Install it with: pip install dcp-ai>=2.8.1"
        ) from exc
    return generate_keypair, sign_object, verify_object


class PolicyEngine:
    """Embedded rule-based policy engine.

    Args:
        ruleset: Parsed :class:`RuleSet` to evaluate against.
        engine_id: Stable identifier surfaced in every signed
            decision. Useful when multiple engines coexist (e.g. one
            per business unit).
        signer_secret_key_b64: Optional pre-generated signing key. If
            omitted, a fresh keypair is created and the public part
            is exposed via :attr:`signer_public_key_b64`.
        signer_public_key_b64: Public counterpart of
            ``signer_secret_key_b64``. Required when secret is given.
    """

    def __init__(
        self,
        ruleset: RuleSet,
        *,
        engine_id: str = "embedded",
        signer_secret_key_b64: str | None = None,
        signer_public_key_b64: str | None = None,
    ) -> None:
        self.ruleset = ruleset
        self.engine_id = engine_id

        generate_keypair, self._sign_object, self._verify_object = _import_dcp_crypto()
        if signer_secret_key_b64 is None:
            kp = generate_keypair()
            self._signer_secret_b64: str = kp["secret_key_b64"]
            self.signer_public_key_b64: str = kp["public_key_b64"]
        else:
            if not signer_public_key_b64:
                raise IdentityError(
                    "signer_public_key_b64 is required when signer_secret_key_b64 is provided"
                )
            self._signer_secret_b64 = signer_secret_key_b64
            self.signer_public_key_b64 = signer_public_key_b64

    # ── factories ─────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyEngine:
        """Build an engine from a YAML policy file."""
        return cls(RuleSet.from_yaml(path))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyEngine:
        """Build an engine from an in-memory dict (tests, programmatic
        construction)."""
        return cls(RuleSet.from_dict(data))

    @classmethod
    def permissive(cls) -> PolicyEngine:
        """Build a default-allow engine. Every intent is approved.

        Useful for onboarding (you want audit trails before you have
        policy coverage). Pair with ``dcp_strict_mode=False`` to run
        in observation mode.
        """
        return cls(RuleSet.permissive(), engine_id="permissive")

    @classmethod
    def from_external(cls, endpoint: str, auth: Any | None = None) -> PolicyEngine:
        """External HTTP engine. Reserved for v0.2.0."""
        raise NotImplementedError(
            "External HTTP policy engines are scheduled for agno-dcp v0.2.0. "
            "Use PolicyEngine.from_yaml() for now."
        )

    # ── evaluation ────────────────────────────────────────────────

    async def evaluate(
        self,
        intent: IntentDeclaration,
        agent_security_tier: str | None = None,
    ) -> PolicyDecision:
        """Evaluate an intent. Returns a signed :class:`PolicyDecision`.

        The intent's signature is NOT verified here; the
        :class:`~agno_dcp.policy.gate.PolicyGate` is the layer that
        verifies the intent before forwarding it.
        """
        # Local import avoids a circular import via gate.py
        from agno_dcp.policy.gate import PolicyDecision

        context: dict[str, Any] = {
            "agent_id": intent.agent_id,
            "action_type": intent.action_type,
            "agent_security_tier": agent_security_tier,
            **{k: v for k, v in intent.action_payload.items() if k != "payload"},
            "payload": intent.action_payload,
        }
        # Hoist tool_name out of payload for ergonomic rules.
        if "tool_name" not in context and "tool_name" in intent.action_payload:
            context["tool_name"] = intent.action_payload["tool_name"]

        verdict, reason, matched_rule = self.ruleset.evaluate(context)
        approved = verdict == "allow"
        conditions = list(matched_rule.conditions) if matched_rule else []
        decision_id = f"dec:{intent.intent_id}"

        decision_payload = {
            "decision_id": decision_id,
            "intent_id": intent.intent_id,
            "agent_id": intent.agent_id,
            "engine_id": self.engine_id,
            "approved": approved,
            "reason": reason,
            "conditions": conditions,
            "rule_name": matched_rule.name if matched_rule else None,
            "evaluated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
        signature_b64 = self._sign_object(decision_payload, self._signer_secret_b64)

        return PolicyDecision(
            decision_id=decision_id,
            intent_id=intent.intent_id,
            agent_id=intent.agent_id,
            engine_id=self.engine_id,
            approved=approved,
            reason=reason,
            conditions=conditions,
            rule_name=matched_rule.name if matched_rule else None,
            evaluated_at=str(decision_payload["evaluated_at"]),
            signature_b64=signature_b64,
            signer_public_key_b64=self.signer_public_key_b64,
        )

    def verify_decision(self, decision: PolicyDecision) -> bool:
        """Verify the signature on a previously issued decision."""
        signable = {
            "decision_id": decision.decision_id,
            "intent_id": decision.intent_id,
            "agent_id": decision.agent_id,
            "engine_id": decision.engine_id,
            "approved": decision.approved,
            "reason": decision.reason,
            "conditions": decision.conditions,
            "rule_name": decision.rule_name,
            "evaluated_at": decision.evaluated_at,
        }
        try:
            return bool(
                self._verify_object(
                    signable, decision.signature_b64, decision.signer_public_key_b64
                )
            )
        except Exception as exc:
            logger.warning("Decision verification raised: %s", exc)
            return False


__all__ = ["ConfigurationError", "PolicyEngine"]
