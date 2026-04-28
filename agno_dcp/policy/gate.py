"""PolicyGate: signs intents, drives the engine, persists decisions.

The gate is the only object the rest of agno-dcp talks to when a
gated action is about to run. It receives a raw action description,
builds and signs an :class:`IntentDeclaration`, asks the
:class:`~agno_dcp.policy.engine.PolicyEngine` for a verdict, persists
both records, emits the corresponding audit events, and returns the
typed :class:`PolicyDecision`.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from agno_dcp.audit.chain import AuditEvent, AuditEventType, MerkleAuditChain
from agno_dcp.exceptions import IdentityError, PolicyDenied

if TYPE_CHECKING:
    from agno_dcp.policy.engine import PolicyEngine


logger = logging.getLogger(__name__)


def _import_dcp_crypto() -> tuple[Any, Any]:
    try:
        from dcp_ai.crypto import (
            sign_object,
            verify_object,
        )
    except ImportError as exc:  # pragma: no cover
        raise IdentityError(
            "dcp_ai SDK is required for intent signing. Install it with: pip install dcp-ai>=2.8.1"
        ) from exc
    return sign_object, verify_object


class IntentDeclaration(BaseModel):
    """A signed declaration that an agent intends to perform an action.

    Attributes:
        intent_id: Unique identifier for this intent.
        agent_id: Which agent is declaring the intent.
        action_type: High-level category, e.g. ``tool_call``,
            ``team_message``, ``mcp_outbound``, ``external_api``.
        action_payload: Free-form action description. The matcher
            walks dotted paths through this dict.
        timestamp: UTC ISO-8601.
        signature_b64: Detached Ed25519 signature over the canonical
            form (excluding ``signature_b64``). Signed with the
            agent's keypair.
        signer_public_key_b64: Public key matching ``signature_b64``.
            Embedded so verifiers can check the signature without
            additional lookups.
    """

    model_config = ConfigDict(extra="forbid")

    intent_id: str
    agent_id: str
    action_type: str
    action_payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    signature_b64: str = ""
    signer_public_key_b64: str = ""

    def to_signable(self) -> dict[str, Any]:
        d = self.model_dump()
        d.pop("signature_b64", None)
        return d

    @classmethod
    def create(
        cls,
        agent_id: str,
        action_type: str,
        action_payload: dict[str, Any],
        secret_key_b64: str,
        public_key_b64: str,
    ) -> IntentDeclaration:
        """Mint and sign a new intent."""
        sign_object, _ = _import_dcp_crypto()
        intent_id = f"intent:{uuid.uuid4().hex[:16]}"
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        intent = cls(
            intent_id=intent_id,
            agent_id=agent_id,
            action_type=action_type,
            action_payload=dict(action_payload),
            timestamp=ts,
            signer_public_key_b64=public_key_b64,
        )
        intent.signature_b64 = sign_object(intent.to_signable(), secret_key_b64)
        return intent

    def verify(self) -> bool:
        """Verify the embedded signature against the embedded pubkey."""
        if not self.signature_b64 or not self.signer_public_key_b64:
            return False
        _, verify_object = _import_dcp_crypto()
        try:
            return bool(
                verify_object(self.to_signable(), self.signature_b64, self.signer_public_key_b64)
            )
        except Exception as exc:
            logger.warning("Intent verification raised: %s", exc)
            return False


class PolicyDecision(BaseModel):
    """A signed allow / deny decision."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str
    intent_id: str
    agent_id: str
    engine_id: str
    approved: bool
    reason: str
    conditions: list[str] = Field(default_factory=list)
    rule_name: str | None = None
    evaluated_at: str
    signature_b64: str
    signer_public_key_b64: str


class PolicyGate:
    """Combines signing, evaluation, persistence, and audit emission.

    Args:
        engine: The :class:`PolicyEngine` to consult.
        audit_chain: The :class:`MerkleAuditChain` to seal events
            into. The gate appends ``INTENT_DECLARED`` and
            ``POLICY_DECISION`` events for every call to
            :meth:`evaluate`.
        strict: If True, raises :class:`PolicyDenied` on a deny.
            If False (default), returns the deny decision and lets the
            caller decide.
    """

    def __init__(
        self,
        engine: PolicyEngine,
        audit_chain: MerkleAuditChain,
        *,
        strict: bool = False,
    ) -> None:
        self.engine = engine
        self.audit_chain = audit_chain
        self.strict = strict

    async def evaluate(
        self,
        intent: IntentDeclaration,
        agent_security_tier: str | None = None,
    ) -> PolicyDecision:
        """Evaluate the intent and persist both intent and decision.

        Verifies the intent's signature first; an unverifiable intent
        is treated as an automatic deny (and emitted as an ERROR audit
        event for forensic visibility).
        """
        if not intent.verify():
            logger.warning(
                "Intent %s for agent %s failed signature verification",
                intent.intent_id,
                intent.agent_id,
            )
            await self.audit_chain.append(
                AuditEvent(
                    event_type=AuditEventType.ERROR,
                    agent_id=intent.agent_id,
                    payload={
                        "intent_id": intent.intent_id,
                        "reason": "intent signature invalid",
                    },
                )
            )
            forced_deny = PolicyDecision(
                decision_id=f"dec:{intent.intent_id}",
                intent_id=intent.intent_id,
                agent_id=intent.agent_id,
                engine_id=self.engine.engine_id,
                approved=False,
                reason="intent signature invalid",
                conditions=[],
                rule_name=None,
                evaluated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                signature_b64="",
                signer_public_key_b64=self.engine.signer_public_key_b64,
            )
            if self.strict:
                raise PolicyDenied(
                    "Intent signature invalid",
                    intent=intent,
                    decision=forced_deny,
                )
            return forced_deny

        await self.audit_chain.storage.put_intent(intent.model_dump())
        await self.audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.INTENT_DECLARED,
                agent_id=intent.agent_id,
                payload=intent.model_dump(),
            )
        )

        decision = await self.engine.evaluate(intent, agent_security_tier)

        await self.audit_chain.storage.put_policy_decision(decision.model_dump())
        await self.audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.POLICY_DECISION,
                agent_id=intent.agent_id,
                payload=decision.model_dump(),
            )
        )

        if not decision.approved and self.strict:
            raise PolicyDenied(decision.reason, intent=intent, decision=decision)
        return decision
