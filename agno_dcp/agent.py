"""DCPAgent: Agno Agent wrapped with DCP-AI governance.

Three responsibilities, in order of construction:

1. Generate or load the agent's :class:`CitizenshipBundle` (DCP-01).
2. Sign every action through the :class:`PolicyGate` (DCP-02).
3. Seal every significant event into the :class:`MerkleAuditChain`
   (DCP-03).

The wrapper is opt-in. Code that builds a plain ``agno.Agent``
continues to work; only callers that explicitly choose
:class:`DCPAgent` pay the governance cost (typically less than 5 ms
per gated action when both the policy engine and the audit chain
are local).

Hook integration with Agno
==========================

Agno exposes pre/post tool-call hooks. The exact hook names and
signatures may evolve; this module exposes governance methods that
the caller (or Agno itself, in a future native integration) can
register::

    agent.dcp_pre_tool_call(tool_name, tool_args)   # awaitable
    agent.dcp_post_tool_call(tool_name, tool_args, result)

Until Agno ships native DCP hooks, the recommended pattern is to
call :meth:`DCPAgent.run_tool` from your tool dispatcher; it wraps
the gating, execution, and audit emission in one call.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from agno_dcp.audit.chain import AuditEvent, AuditEventType, MerkleAuditChain
from agno_dcp.exceptions import ConfigurationError, PolicyDenied
from agno_dcp.identity import (
    CitizenshipBundle,
    SecurityTier,
    generate_citizenship_bundle,
)
from agno_dcp.policy.engine import PolicyEngine
from agno_dcp.policy.gate import IntentDeclaration, PolicyDecision, PolicyGate
from agno_dcp.storage.base import BaseStorage
from agno_dcp.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


# DECISION PENDING: Agno's exact public Agent class location may shift.
# Today the brief specifies ``agno.agent.Agent``. We import lazily and
# fall back to a stub so the package loads without agno installed
# (useful for unit tests that mock everything).
try:
    from agno.agent import Agent as _AgnoAgent

    _AGNO_AVAILABLE = True
except ImportError:
    _AGNO_AVAILABLE = False

    class _AgnoAgent:  # type: ignore[no-redef]
        """Stub used when ``agno`` is not installed at import time.

        Construction stores the kwargs so tests can introspect them.
        Instantiating :class:`DCPAgent` against this stub still works
        for unit testing the DCP-AI surface; production callers must
        install ``agno>=2.0.0``.
        """

        def __init__(self, **kwargs: Any) -> None:
            self._agno_stub_kwargs = kwargs


class DCPAgent(_AgnoAgent):  # type: ignore[misc]  # _AgnoAgent is dynamically typed
    """Agno Agent extended with DCP-AI governance.

    Args:
        dcp_human_principal: Required. Email or DID of the responsible
            human. Becomes part of the Citizenship Bundle.
        dcp_security_tier: Adaptive security tier the agent commits
            to. Defaults to ``tier-2``.
        dcp_policy_engine: Optional :class:`PolicyEngine`. Defaults to
            a permissive engine (allow-all, decisions still signed).
        dcp_audit_chain: Optional :class:`MerkleAuditChain`. Defaults
            to a chain backed by an in-memory SQLite (development
            only; pass an explicit chain for production).
        dcp_storage: Optional shared :class:`BaseStorage`. If
            provided and ``dcp_audit_chain`` is not, an audit chain
            is constructed against this storage.
        dcp_strict_mode: If True, a deny verdict raises
            :class:`PolicyDenied` and the tool does not run. If False
            (default), the deny is logged and audited but the tool
            still runs (observation mode).
        dcp_existing_bundle: Optional pre-existing
            :class:`CitizenshipBundle`. When provided, also requires
            ``dcp_secret_key_b64``. Used for agent restart or
            multi-process scenarios.
        dcp_secret_key_b64: Secret key matching
            ``dcp_existing_bundle.public_key_b64``. Required if a
            bundle is supplied.
        **agno_kwargs: Forwarded verbatim to Agno's ``Agent.__init__``.

    Attributes:
        dcp_bundle: The :class:`CitizenshipBundle` for this agent.
        dcp_security_tier: Resolved security tier.
        dcp_strict_mode: Whether deny verdicts raise.
        dcp_audit_chain: The audit chain in use.
        dcp_policy_gate: The gate that mediates tool calls.
    """

    def __init__(
        self,
        *,
        dcp_human_principal: str,
        dcp_security_tier: SecurityTier = "tier-2",
        dcp_policy_engine: PolicyEngine | None = None,
        dcp_audit_chain: MerkleAuditChain | None = None,
        dcp_storage: BaseStorage | None = None,
        dcp_strict_mode: bool = False,
        dcp_existing_bundle: CitizenshipBundle | None = None,
        dcp_secret_key_b64: str | None = None,
        **agno_kwargs: Any,
    ) -> None:
        if not dcp_human_principal:
            raise ConfigurationError("dcp_human_principal is required for DCPAgent")

        agent_name = agno_kwargs.get("name", "agno-agent")

        # Defer Agno parent init until DCP fields are settled. We
        # forward everything Agno-flavoured at the end so any Agno
        # validation runs after our own.
        super().__init__(**agno_kwargs)

        self.dcp_human_principal: str = dcp_human_principal
        self.dcp_security_tier: SecurityTier = dcp_security_tier
        self.dcp_strict_mode: bool = dcp_strict_mode

        # Identity
        if dcp_existing_bundle is not None:
            if not dcp_secret_key_b64:
                raise ConfigurationError(
                    "dcp_secret_key_b64 is required when dcp_existing_bundle is provided"
                )
            self.dcp_bundle: CitizenshipBundle = dcp_existing_bundle
            self._dcp_secret_b64: str = dcp_secret_key_b64
        else:
            bundle, secret = generate_citizenship_bundle(
                agent_name=agent_name,
                human_principal=dcp_human_principal,
                security_tier=dcp_security_tier,
            )
            self.dcp_bundle = bundle
            self._dcp_secret_b64 = secret

        # Storage and audit chain
        if dcp_audit_chain is not None:
            self.dcp_audit_chain: MerkleAuditChain = dcp_audit_chain
        else:
            storage = dcp_storage or SQLiteStorage(":memory:")
            self.dcp_audit_chain = MerkleAuditChain(storage=storage)
        self._dcp_storage: BaseStorage = self.dcp_audit_chain.storage

        # Policy engine (default permissive)
        engine = dcp_policy_engine or PolicyEngine.permissive()
        self.dcp_policy_gate: PolicyGate = PolicyGate(
            engine=engine,
            audit_chain=self.dcp_audit_chain,
            strict=dcp_strict_mode,
        )

        self._dcp_initialized = False
        logger.info(
            "DCPAgent constructed agent_id=%s tier=%s strict=%s",
            self.dcp_bundle.agent_id,
            dcp_security_tier,
            dcp_strict_mode,
        )

    async def dcp_initialize(self) -> None:
        """Run async initialization (storage migration, AGENT_CREATED).

        Safe to call multiple times; only the first call performs work.
        Required before the first call to :meth:`run_tool` or
        :meth:`dcp_pre_tool_call`.
        """
        if self._dcp_initialized:
            return
        await self._dcp_storage.initialize()
        await self._dcp_storage.put_citizenship_bundle(self.dcp_bundle.model_dump())
        await self.dcp_audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.AGENT_CREATED,
                agent_id=self.dcp_bundle.agent_id,
                payload={
                    "agent_name": self.dcp_bundle.agent_name,
                    "human_principal": self.dcp_bundle.human_principal,
                    "security_tier": self.dcp_bundle.security_tier,
                },
            )
        )
        self._dcp_initialized = True

    # ── intent and gating ─────────────────────────────────────────

    def dcp_build_intent(
        self,
        action_type: str,
        action_payload: dict[str, Any],
    ) -> IntentDeclaration:
        """Build and sign an :class:`IntentDeclaration` for an action."""
        return IntentDeclaration.create(
            agent_id=self.dcp_bundle.agent_id,
            action_type=action_type,
            action_payload=action_payload,
            secret_key_b64=self._dcp_secret_b64,
            public_key_b64=self.dcp_bundle.public_key_b64,
        )

    async def dcp_pre_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Hook invoked before a tool runs. Returns the gate decision.

        In strict mode raises :class:`PolicyDenied` on a deny. In
        observation mode returns the decision and lets the caller
        decide.
        """
        if not self._dcp_initialized:
            await self.dcp_initialize()
        intent = self.dcp_build_intent(
            action_type="tool_call",
            action_payload={"tool_name": tool_name, **(tool_args or {})},
        )
        return await self.dcp_policy_gate.evaluate(
            intent, agent_security_tier=self.dcp_security_tier
        )

    async def dcp_post_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None,
        result: Any,
        *,
        error: BaseException | None = None,
    ) -> None:
        """Hook invoked after a tool runs. Seals a TOOL_EXECUTED event.

        On error, also seals an ERROR event.
        """
        if not self._dcp_initialized:
            await self.dcp_initialize()
        await self.dcp_audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTED,
                agent_id=self.dcp_bundle.agent_id,
                payload={
                    "tool_name": tool_name,
                    "tool_args": tool_args or {},
                    "ok": error is None,
                    "result_summary": _summarize(result) if error is None else None,
                },
            )
        )
        if error is not None:
            await self.dcp_audit_chain.append(
                AuditEvent(
                    event_type=AuditEventType.ERROR,
                    agent_id=self.dcp_bundle.agent_id,
                    payload={
                        "tool_name": tool_name,
                        "error_type": type(error).__name__,
                        "error_message": str(error),
                    },
                )
            )

    async def run_tool(
        self,
        tool: Callable[..., Any],
        tool_args: dict[str, Any] | None = None,
        *,
        tool_name: str | None = None,
    ) -> Any:
        """Run a tool through the full DCP-AI pipeline.

        1. Build and sign intent
        2. Gate through PolicyEngine (deny may raise in strict mode)
        3. Execute the tool (sync or async)
        4. Audit the execution
        5. Return the tool's result

        Args:
            tool: The callable to execute. Sync callables are run via
                ``asyncio.to_thread`` to keep the event loop free.
            tool_args: Arguments forwarded to the tool. Defaults to
                an empty dict.
            tool_name: Override the tool name used in the intent and
                audit events. Defaults to ``tool.__name__``.

        Returns:
            Whatever the tool returns.

        Raises:
            PolicyDenied: In strict mode, on a deny verdict.
            Exception: Any error raised by the tool itself, after the
                ERROR audit entry has been recorded.
        """
        import asyncio
        import inspect

        if not self._dcp_initialized:
            await self.dcp_initialize()

        name: str = tool_name or str(getattr(tool, "__name__", "anonymous_tool"))
        args = tool_args or {}

        decision = await self.dcp_pre_tool_call(name, args)
        if not decision.approved:
            if self.dcp_strict_mode:
                # PolicyGate already raised; defensive guard.
                raise PolicyDenied(decision.reason, decision=decision)
            logger.warning(
                "Policy denied tool %s for agent %s; observation mode permits execution",
                name,
                self.dcp_bundle.agent_id,
            )

        try:
            if inspect.iscoroutinefunction(tool):
                result = await tool(**args)
            else:
                result = await asyncio.to_thread(lambda: tool(**args))
        except Exception as exc:
            await self.dcp_post_tool_call(name, args, None, error=exc)
            raise

        await self.dcp_post_tool_call(name, args, result)
        return result


def _summarize(value: Any) -> str:
    """Compact textual summary of a tool result for audit payloads.

    The full result is expected to be available elsewhere (the
    application's response, model output, etc.). The audit chain only
    needs a fingerprint, not the bytes.
    """
    text = repr(value)
    if len(text) > 200:
        return text[:197] + "..."
    return text


__all__ = ["DCPAgent"]
