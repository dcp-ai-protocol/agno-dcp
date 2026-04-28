"""DCPWorkflow: Agno Workflow with per-step audit and gating.

Every step in the workflow is sealed into the audit chain. If a step
violates policy, the workflow halts in strict mode (raising
:class:`PolicyDenied`) or continues with a flagged step in
observation mode.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC
from typing import Any

from agno_dcp.audit.chain import AuditEvent, AuditEventType, MerkleAuditChain
from agno_dcp.exceptions import ConfigurationError, PolicyDenied
from agno_dcp.policy.engine import PolicyEngine
from agno_dcp.policy.gate import IntentDeclaration, PolicyGate
from agno_dcp.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


# DECISION PENDING: same lazy-import pattern as DCPAgent.
try:
    from agno.workflow import Workflow as _AgnoWorkflow

    _AGNO_WORKFLOW_AVAILABLE = True
except ImportError:
    _AGNO_WORKFLOW_AVAILABLE = False

    class _AgnoWorkflow:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            self._agno_stub_kwargs = kwargs


class DCPWorkflow(_AgnoWorkflow):  # type: ignore[misc]  # _AgnoWorkflow is dynamically typed
    """Agno Workflow extended with per-step DCP-AI audit and gating.

    Args:
        dcp_workflow_id: Stable identifier surfaced in every step's
            audit payload.
        dcp_audit_chain: Optional shared audit chain. Defaults to a
            new chain on in-memory SQLite.
        dcp_policy_engine: Optional policy engine. Defaults to
            permissive.
        dcp_strict_mode: If True, a denied step raises
            :class:`PolicyDenied` and the workflow halts.
        **agno_kwargs: Forwarded to ``agno.workflow.Workflow``.
    """

    def __init__(
        self,
        *,
        dcp_workflow_id: str,
        dcp_human_principal: str,
        dcp_audit_chain: MerkleAuditChain | None = None,
        dcp_policy_engine: PolicyEngine | None = None,
        dcp_strict_mode: bool = False,
        **agno_kwargs: Any,
    ) -> None:
        if not dcp_workflow_id:
            raise ConfigurationError("dcp_workflow_id is required for DCPWorkflow")
        super().__init__(**agno_kwargs)

        self.dcp_workflow_id: str = dcp_workflow_id
        self.dcp_human_principal: str = dcp_human_principal
        self.dcp_strict_mode: bool = dcp_strict_mode

        if dcp_audit_chain is None:
            storage = SQLiteStorage(":memory:")
            dcp_audit_chain = MerkleAuditChain(storage=storage)
        self.dcp_audit_chain: MerkleAuditChain = dcp_audit_chain

        engine = dcp_policy_engine or PolicyEngine.permissive()
        self.dcp_policy_gate: PolicyGate = PolicyGate(
            engine=engine,
            audit_chain=self.dcp_audit_chain,
            strict=dcp_strict_mode,
        )
        self._dcp_initialized = False

    async def dcp_initialize(self) -> None:
        if self._dcp_initialized:
            return
        await self.dcp_audit_chain.storage.initialize()
        self._dcp_initialized = True

    async def run_step(
        self,
        step_name: str,
        step_fn: Callable[..., Any],
        step_args: dict[str, Any] | None = None,
    ) -> Any:
        """Run one workflow step under DCP-AI governance.

        Builds an intent for the step, gates it, executes, and seals
        a WORKFLOW_STEP audit event. The step function may be sync or
        async. Sync functions run in a thread to keep the event loop
        free.
        """
        import asyncio
        import inspect
        import uuid as _uuid
        from datetime import datetime

        if not self._dcp_initialized:
            await self.dcp_initialize()
        args = step_args or {}

        # Build a workflow-scoped intent. We do not have a per-agent
        # signing key here (workflows are infrastructure), so the gate
        # signs an unsigned intent under a "workflow-internal"
        # convention. The audit chain still covers integrity.
        synthetic_pubkey = self.dcp_audit_chain.signer_public_key_b64
        intent_id = f"intent:wf:{_uuid.uuid4().hex[:16]}"
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        intent = IntentDeclaration(
            intent_id=intent_id,
            agent_id=f"workflow:{self.dcp_workflow_id}",
            action_type="workflow_step",
            action_payload={"step_name": step_name, **args},
            timestamp=ts,
            signature_b64="",
            signer_public_key_b64=synthetic_pubkey,
        )

        # Self-sign with the audit chain's keypair so the intent
        # remains verifiable end-to-end.
        from dcp_ai.crypto import sign_object

        intent.signature_b64 = sign_object(
            intent.to_signable(), self.dcp_audit_chain._signer_secret_b64
        )

        decision = await self.dcp_policy_gate.evaluate(intent)
        if not decision.approved and self.dcp_strict_mode:
            raise PolicyDenied(decision.reason, intent=intent, decision=decision)

        try:
            if inspect.iscoroutinefunction(step_fn):
                result = await step_fn(**args)
            else:
                result = await asyncio.to_thread(lambda: step_fn(**args))
        except Exception as exc:
            await self.dcp_audit_chain.append(
                AuditEvent(
                    event_type=AuditEventType.ERROR,
                    agent_id=f"workflow:{self.dcp_workflow_id}",
                    payload={
                        "step_name": step_name,
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    },
                )
            )
            raise

        await self.dcp_audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.WORKFLOW_STEP,
                agent_id=f"workflow:{self.dcp_workflow_id}",
                payload={
                    "step_name": step_name,
                    "approved": decision.approved,
                    "ok": True,
                },
            )
        )
        return result


__all__ = ["DCPWorkflow"]
