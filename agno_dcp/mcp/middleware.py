"""MCP signing and verification middleware.

The wire envelope adds three fields to a normal MCP message body:

* ``dcp_signer_public_key_b64`` (Ed25519 base64)
* ``dcp_signature_b64`` (Ed25519 detached signature over the canonical
  form of the message excluding ``dcp_*`` envelope fields)
* ``dcp_signed_at`` (ISO-8601 UTC)

Receivers that do not understand the envelope simply ignore the extra
fields. Receivers that do can verify the signature and route the
message accordingly.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from agno_dcp.audit.chain import AuditEvent, AuditEventType
from agno_dcp.exceptions import IdentityError, MCPVerificationError

if TYPE_CHECKING:
    from agno_dcp.audit.chain import MerkleAuditChain


logger = logging.getLogger(__name__)


_ENVELOPE_FIELDS = ("dcp_signer_public_key_b64", "dcp_signature_b64", "dcp_signed_at")


def _import_dcp_crypto() -> tuple[Any, Any]:
    try:
        from dcp_ai.crypto import (
            sign_object,
            verify_object,
        )
    except ImportError as exc:  # pragma: no cover
        raise IdentityError(
            "dcp_ai SDK is required for MCP signing. Install it with: pip install dcp-ai>=2.8.1"
        ) from exc
    return sign_object, verify_object


class MCPEnvelope(BaseModel):
    """The DCP-AI envelope fields wrapping an MCP message body."""

    model_config = ConfigDict(extra="forbid")

    dcp_signer_public_key_b64: str
    dcp_signature_b64: str
    dcp_signed_at: str


def _strip_envelope(message: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of the message minus envelope fields."""
    return {k: v for k, v in message.items() if k not in _ENVELOPE_FIELDS}


def sign_mcp_message(
    message: dict[str, Any],
    secret_key_b64: str,
    public_key_b64: str,
) -> dict[str, Any]:
    """Wrap an outbound MCP message with a DCP-AI signature envelope.

    Args:
        message: The MCP message body. Must be JSON-serializable.
        secret_key_b64: Sender's Ed25519 secret key, base64 encoded.
        public_key_b64: Sender's Ed25519 public key, base64 encoded.
            Embedded in the envelope so the receiver can verify
            without prior key exchange.

    Returns:
        A new dict with the original message plus envelope fields.
        The original ``message`` is not mutated.
    """
    sign_object, _ = _import_dcp_crypto()
    body = _strip_envelope(dict(message))
    signed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    body_with_meta = {**body, "dcp_signed_at": signed_at}
    signature = sign_object(body_with_meta, secret_key_b64)
    return {
        **body,
        "dcp_signer_public_key_b64": public_key_b64,
        "dcp_signature_b64": signature,
        "dcp_signed_at": signed_at,
    }


def verify_mcp_message(message: dict[str, Any]) -> bool:
    """Verify a DCP-AI envelope on an inbound MCP message.

    Returns ``True`` if the envelope is present and the signature is
    valid against the embedded public key. Returns ``False`` if the
    envelope is missing (peer is not DCP-AI capable) or invalid.

    Distinguish "missing envelope" from "invalid envelope" with
    :func:`has_envelope`.
    """
    if not has_envelope(message):
        return False
    _, verify_object = _import_dcp_crypto()
    body = _strip_envelope(message)
    body_with_meta = {**body, "dcp_signed_at": message["dcp_signed_at"]}
    try:
        return bool(
            verify_object(
                body_with_meta,
                message["dcp_signature_b64"],
                message["dcp_signer_public_key_b64"],
            )
        )
    except Exception as exc:
        logger.warning("MCP verify raised: %s", exc)
        return False


def has_envelope(message: dict[str, Any]) -> bool:
    """Return True iff every envelope field is present on the message."""
    return all(field in message for field in _ENVELOPE_FIELDS)


class DCPMCPMiddleware:
    """Stateful middleware bound to a single agent identity.

    Args:
        agent_id: Identifier surfaced in audit events.
        secret_key_b64: Agent's Ed25519 secret key.
        public_key_b64: Agent's Ed25519 public key.
        audit_chain: Optional audit chain to seal MCP_INBOUND and
            MCP_OUTBOUND events into. If ``None``, signing and
            verification still work but no events are recorded.
        strict_inbound: If ``True``, an inbound message that has an
            envelope but fails verification raises
            :class:`MCPVerificationError`. If ``False`` (default), the
            message is logged and dropped to ``None``.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        secret_key_b64: str,
        public_key_b64: str,
        audit_chain: MerkleAuditChain | None = None,
        strict_inbound: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self._secret_b64 = secret_key_b64
        self.public_key_b64 = public_key_b64
        self.audit_chain = audit_chain
        self.strict_inbound = strict_inbound

    async def sign_outbound(self, message: dict[str, Any]) -> dict[str, Any]:
        """Sign an outbound MCP message and seal an MCP_OUTBOUND audit
        event. Returns the wrapped message."""
        wrapped = sign_mcp_message(message, self._secret_b64, self.public_key_b64)
        if self.audit_chain is not None:
            await self.audit_chain.append(
                AuditEvent(
                    event_type=AuditEventType.MCP_OUTBOUND,
                    agent_id=self.agent_id,
                    payload={"signed_at": wrapped["dcp_signed_at"]},
                )
            )
        return wrapped

    async def verify_inbound(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Verify an inbound message and seal an MCP_INBOUND audit
        event.

        Returns the inbound message stripped of envelope fields when
        verification succeeds. Returns ``None`` (or raises in strict
        mode) when verification fails. Returns the message verbatim
        if no envelope is present (peer is not DCP-AI capable).
        """
        if not has_envelope(message):
            return message
        ok = verify_mcp_message(message)
        if self.audit_chain is not None:
            await self.audit_chain.append(
                AuditEvent(
                    event_type=AuditEventType.MCP_INBOUND,
                    agent_id=self.agent_id,
                    payload={
                        "signer_public_key_b64": message.get("dcp_signer_public_key_b64", ""),
                        "verified": ok,
                        "signed_at": message.get("dcp_signed_at"),
                    },
                )
            )
        if not ok:
            if self.strict_inbound:
                raise MCPVerificationError(
                    "Inbound MCP message failed signature verification",
                    message=message,
                )
            return None
        return _strip_envelope(message)


__all__ = [
    "DCPMCPMiddleware",
    "MCPEnvelope",
    "has_envelope",
    "sign_mcp_message",
    "verify_mcp_message",
]
