"""DCPTeam: Agno Team wrapped with team-level identity and shared
audit chain.

Each team has its own Citizenship Bundle (the team's responsible
principal + the team's keypair). Each member that is a
:class:`DCPAgent` keeps its own bundle. Team-level events
(member joined, message between members, team decision) are sealed
into the same audit chain that members write to, so an external
auditor sees a coherent ordering of agent actions and team
coordination.
"""

from __future__ import annotations

import logging
from typing import Any

from agno_dcp.agent import DCPAgent
from agno_dcp.audit.chain import AuditEvent, AuditEventType, MerkleAuditChain
from agno_dcp.exceptions import ConfigurationError
from agno_dcp.identity import (
    CitizenshipBundle,
    SecurityTier,
    generate_citizenship_bundle,
)
from agno_dcp.policy.engine import PolicyEngine
from agno_dcp.policy.gate import PolicyGate
from agno_dcp.storage.base import BaseStorage
from agno_dcp.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


# DECISION PENDING: same lazy-import pattern as DCPAgent.
try:
    from agno.team import Team as _AgnoTeam

    _AGNO_TEAM_AVAILABLE = True
except ImportError:
    _AGNO_TEAM_AVAILABLE = False

    class _AgnoTeam:  # type: ignore[no-redef]
        """Stub used when ``agno`` is not installed at import time."""

        def __init__(self, **kwargs: Any) -> None:
            self._agno_stub_kwargs = kwargs


class DCPTeam(_AgnoTeam):  # type: ignore[misc]  # _AgnoTeam is dynamically typed
    """Agno Team plus team-level Citizenship Bundle and shared audit.

    Args:
        dcp_team_name: Display name for the team. Used as the bundle's
            ``agent_name`` (the bundle schema reuses the agent slot
            for the team's own identity).
        dcp_human_principal: Required. Responsible principal for the
            team (typically a team lead or organisation).
        dcp_security_tier: Default security tier for team-level
            events. Individual members keep their own tiers.
        dcp_policy_engine: Optional shared policy engine. Defaults to
            permissive.
        dcp_audit_chain: Optional shared audit chain. Defaults to a
            new chain on in-memory SQLite.
        dcp_storage: Optional shared storage. Used to construct an
            audit chain when ``dcp_audit_chain`` is not given.
        dcp_strict_mode: Forwarded to the team-level PolicyGate.
        members: Iterable of :class:`DCPAgent` (or plain Agno Agent)
            members. DCPAgent members will reuse the team's audit
            chain when their own chain is not explicitly set.
        **agno_kwargs: Forwarded to ``agno.team.Team.__init__``.
    """

    def __init__(
        self,
        *,
        dcp_team_name: str,
        dcp_human_principal: str,
        dcp_security_tier: SecurityTier = "tier-2",
        dcp_policy_engine: PolicyEngine | None = None,
        dcp_audit_chain: MerkleAuditChain | None = None,
        dcp_storage: BaseStorage | None = None,
        dcp_strict_mode: bool = False,
        members: list[Any] | None = None,
        **agno_kwargs: Any,
    ) -> None:
        if not dcp_team_name:
            raise ConfigurationError("dcp_team_name is required for DCPTeam")
        if not dcp_human_principal:
            raise ConfigurationError("dcp_human_principal is required for DCPTeam")

        # Forward members to Agno (it expects them).
        if members is not None:
            agno_kwargs.setdefault("members", members)
        super().__init__(**agno_kwargs)

        self.dcp_team_name: str = dcp_team_name
        self.dcp_security_tier: SecurityTier = dcp_security_tier
        self.dcp_strict_mode: bool = dcp_strict_mode

        bundle, secret = generate_citizenship_bundle(
            agent_name=dcp_team_name,
            human_principal=dcp_human_principal,
            security_tier=dcp_security_tier,
            metadata={"kind": "team"},
        )
        self.dcp_bundle: CitizenshipBundle = bundle
        self._dcp_secret_b64: str = secret

        if dcp_audit_chain is not None:
            self.dcp_audit_chain: MerkleAuditChain = dcp_audit_chain
        else:
            storage = dcp_storage or SQLiteStorage(":memory:")
            self.dcp_audit_chain = MerkleAuditChain(storage=storage)

        engine = dcp_policy_engine or PolicyEngine.permissive()
        self.dcp_policy_gate: PolicyGate = PolicyGate(
            engine=engine,
            audit_chain=self.dcp_audit_chain,
            strict=dcp_strict_mode,
        )

        self.members: list[Any] = list(members) if members else []
        for m in self.members:
            if isinstance(m, DCPAgent):
                # Share the chain so all members write to the same log.
                m.dcp_audit_chain = self.dcp_audit_chain
                m.dcp_policy_gate = PolicyGate(
                    engine=m.dcp_policy_gate.engine,
                    audit_chain=self.dcp_audit_chain,
                    strict=m.dcp_strict_mode,
                )

        self._dcp_initialized = False
        logger.info(
            "DCPTeam constructed name=%s members=%d",
            dcp_team_name,
            len(self.members),
        )

    async def dcp_initialize(self) -> None:
        """Initialize team storage and seal the team's AGENT_CREATED."""
        if self._dcp_initialized:
            return
        await self.dcp_audit_chain.storage.initialize()
        await self.dcp_audit_chain.storage.put_citizenship_bundle(self.dcp_bundle.model_dump())
        await self.dcp_audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.AGENT_CREATED,
                agent_id=self.dcp_bundle.agent_id,
                payload={
                    "team_name": self.dcp_team_name,
                    "human_principal": self.dcp_bundle.human_principal,
                    "security_tier": self.dcp_security_tier,
                    "members": [
                        m.dcp_bundle.agent_id for m in self.members if isinstance(m, DCPAgent)
                    ],
                },
            )
        )
        for m in self.members:
            if isinstance(m, DCPAgent):
                await m.dcp_initialize()
        self._dcp_initialized = True

    async def emit_team_message(
        self,
        from_agent: DCPAgent,
        to_agent: DCPAgent,
        content: dict[str, Any],
    ) -> None:
        """Seal an inter-member message into the audit chain.

        The message body is stored verbatim; encrypt at the storage
        layer if it can carry sensitive payloads.
        """
        if not self._dcp_initialized:
            await self.dcp_initialize()
        await self.dcp_audit_chain.append(
            AuditEvent(
                event_type=AuditEventType.TEAM_MESSAGE,
                agent_id=self.dcp_bundle.agent_id,
                payload={
                    "from": from_agent.dcp_bundle.agent_id,
                    "to": to_agent.dcp_bundle.agent_id,
                    "content": content,
                },
            )
        )


__all__ = ["DCPTeam"]
