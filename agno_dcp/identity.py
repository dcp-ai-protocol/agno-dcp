"""Citizenship Bundle generation, loading, and verification (DCP-01).

A :class:`CitizenshipBundle` is the cryptographic identity record that
binds an agent to its responsible human principal. It carries the
public key (used to verify everything the agent later signs), the
declared security tier, and a self-signature that proves the bundle
has not been tampered with after creation.

This module delegates all cryptographic primitives to the upstream
``dcp_ai`` SDK (Ed25519 base, ML-DSA-65 composite under the v2 profile
when ``security_tier`` is ``tier-3`` or ``tier-4``). It does not
re-implement signing, hashing, or canonicalization.

Storage of secret keys is the caller's responsibility. The public
helpers in this module return a tuple of ``(bundle, secret_key_b64)``
so the caller can persist the secret in a secrets manager, KMS, or
encrypted at rest. The bundle itself contains only public material.

Example:
    >>> from agno_dcp.identity import generate_citizenship_bundle
    >>> bundle, secret = generate_citizenship_bundle(
    ...     agent_name="Collections Agent",
    ...     human_principal="ops@example.com",
    ...     security_tier="tier-2",
    ... )
    >>> bundle.agent_id.startswith("agent:")
    True
    >>> verify_citizenship_bundle(bundle)
    True
"""

from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agno_dcp.exceptions import IdentityError

if TYPE_CHECKING:
    from agno_dcp.storage.base import BaseStorage


logger = logging.getLogger(__name__)


SecurityTier = Literal["tier-1", "tier-2", "tier-3", "tier-4"]
"""DCP-AI adaptive security tiers.

* ``tier-1`` (Routine): Ed25519 only, suitable for read-only or
  low-risk actions.
* ``tier-2`` (Standard): Ed25519, hybrid preferred, default for most
  agents.
* ``tier-3`` (Elevated): Hybrid Ed25519 plus ML-DSA-65 composite
  required, suitable for PII or financial actions.
* ``tier-4`` (Maximum): Hybrid plus immediate verification plus
  anchored audit, suitable for critical infrastructure.
"""


class CitizenshipBundle(BaseModel):
    """An agent identity record signed by its responsible principal.

    Attributes:
        bundle_id: Unique identifier for this bundle revision. Stable
            across reloads; rotated only when the bundle is re-signed.
        agent_id: Stable identifier for the agent. Format
            ``agent:<short-uuid>``.
        agent_name: Human readable label provided at creation. Not
            unique. Not used for routing.
        human_principal: Identifier of the responsible human or
            organisation (typically an email or DID). Bound to the
            bundle so revocation can target a principal.
        security_tier: Declared adaptive security tier. Determines
            which crypto primitives this agent must use.
        public_key_b64: Base64 encoded Ed25519 public key. Used by
            verifiers to validate every artifact the agent later
            signs.
        created_at: UTC ISO-8601 timestamp of bundle creation.
        metadata: Caller-supplied free-form metadata. Indexed neither
            by the library nor by storage; opaque payload.
        signature_b64: Detached Ed25519 signature over the bundle's
            canonical form (excluding ``signature_b64`` itself). Self
            signed by the agent's keypair at creation time. Verifying
            this signature with ``public_key_b64`` proves the bundle
            has not been altered after creation.
    """

    model_config = ConfigDict(extra="forbid", frozen=False)

    bundle_id: str
    agent_id: str
    agent_name: str
    human_principal: str
    security_tier: SecurityTier
    public_key_b64: str
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    signature_b64: str = ""

    def to_signable(self) -> dict[str, Any]:
        """Return the dict that the signature is computed over.

        Excludes ``signature_b64`` so the signed payload does not
        depend on its own signature.
        """
        d = self.model_dump()
        d.pop("signature_b64", None)
        return d


def _utcnow_iso() -> str:
    """Return the current UTC time in ISO-8601 with seconds precision."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_agent_id() -> str:
    """Mint a new opaque agent identifier."""
    return f"agent:{uuid.uuid4().hex[:16]}"


def _new_bundle_id() -> str:
    """Mint a new opaque bundle identifier."""
    return f"bundle:{secrets.token_hex(8)}"


def _import_dcp_crypto() -> tuple[Any, Any, Any]:
    """Lazy import of the dcp_ai crypto primitives.

    Importing inside a function lets the rest of the package load even
    if ``dcp_ai`` is not yet installed (useful in CI before deps are
    pinned). Raises a clear :class:`IdentityError` if it is missing at
    runtime.
    """
    try:
        from dcp_ai.crypto import (
            generate_keypair,
            sign_object,
            verify_object,
        )
    except ImportError as exc:  # pragma: no cover
        raise IdentityError(
            "dcp_ai SDK is required for identity operations. "
            "Install it with: pip install dcp-ai>=2.8.1"
        ) from exc
    return generate_keypair, sign_object, verify_object


def generate_citizenship_bundle(
    agent_name: str,
    human_principal: str,
    security_tier: SecurityTier = "tier-2",
    metadata: dict[str, Any] | None = None,
) -> tuple[CitizenshipBundle, str]:
    """Create a new Citizenship Bundle and the corresponding secret key.

    The bundle is self-signed: the freshly generated keypair signs the
    bundle's canonical form so any later mutation invalidates the
    signature. The caller receives the secret key separately so it can
    decide where to store it (KMS, secrets manager, encrypted disk).
    The bundle itself only contains public material and is safe to
    share.

    Args:
        agent_name: Display name for the agent.
        human_principal: Responsible human or organisation identifier.
        security_tier: Adaptive security tier the agent commits to.
            Defaults to ``tier-2``.
        metadata: Optional arbitrary metadata. Persisted as-is.

    Returns:
        A tuple ``(bundle, secret_key_b64)``. The bundle is ready to
        store; the secret key must be persisted securely by the
        caller and never logged.

    Raises:
        IdentityError: If ``agent_name`` or ``human_principal`` is
            empty, or if the underlying ``dcp_ai`` SDK is not
            available.
    """
    if not agent_name or not agent_name.strip():
        raise IdentityError("agent_name must be a non-empty string")
    if not human_principal or not human_principal.strip():
        raise IdentityError("human_principal must be a non-empty string")

    generate_keypair, sign_object, _ = _import_dcp_crypto()

    keypair = generate_keypair()
    public_key_b64: str = keypair["public_key_b64"]
    secret_key_b64: str = keypair["secret_key_b64"]

    bundle = CitizenshipBundle(
        bundle_id=_new_bundle_id(),
        agent_id=_new_agent_id(),
        agent_name=agent_name.strip(),
        human_principal=human_principal.strip(),
        security_tier=security_tier,
        public_key_b64=public_key_b64,
        created_at=_utcnow_iso(),
        metadata=dict(metadata) if metadata else {},
        signature_b64="",
    )

    bundle.signature_b64 = sign_object(bundle.to_signable(), secret_key_b64)
    logger.debug(
        "Generated CitizenshipBundle agent_id=%s tier=%s",
        bundle.agent_id,
        security_tier,
    )
    return bundle, secret_key_b64


async def load_citizenship_bundle(
    agent_id: str,
    storage: BaseStorage,
) -> CitizenshipBundle:
    """Load a previously persisted Citizenship Bundle by ``agent_id``.

    The bundle's signature is verified before it is returned. Callers
    that want the bundle without verification (for forensic
    inspection) should query the storage layer directly.

    Args:
        agent_id: The opaque agent identifier returned at creation
            time.
        storage: Backend that knows how to fetch a bundle by id. Must
            implement :meth:`BaseStorage.get_citizenship_bundle`.

    Returns:
        The bundle, signature-verified.

    Raises:
        IdentityError: If the bundle does not exist, or if its
            signature fails verification.
    """
    raw = await storage.get_citizenship_bundle(agent_id)
    if raw is None:
        raise IdentityError(f"No CitizenshipBundle found for agent_id={agent_id}")

    try:
        bundle = CitizenshipBundle.model_validate(raw)
    except Exception as exc:
        raise IdentityError(f"Stored bundle for {agent_id} failed schema validation") from exc

    if not verify_citizenship_bundle(bundle):
        raise IdentityError(
            f"Stored bundle for {agent_id} failed signature verification (possible tampering)"
        )
    return bundle


def verify_citizenship_bundle(bundle: CitizenshipBundle) -> bool:
    """Verify a bundle's self-signature.

    Returns ``True`` if the signature embedded in the bundle is valid
    against the bundle's own ``public_key_b64``. Returns ``False`` for
    any failure mode (missing signature, malformed key, signature
    mismatch). Does not raise on bad signatures; raises only on
    operational failures (SDK not installed).

    Args:
        bundle: The bundle to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    if not bundle.signature_b64:
        logger.warning("CitizenshipBundle %s has no signature", bundle.agent_id)
        return False

    _, _, verify_object = _import_dcp_crypto()
    try:
        return bool(
            verify_object(
                bundle.to_signable(),
                bundle.signature_b64,
                bundle.public_key_b64,
            )
        )
    except Exception as exc:
        logger.warning(
            "CitizenshipBundle verification raised for %s: %s",
            bundle.agent_id,
            exc,
        )
        return False


def serialize_bundle(bundle: CitizenshipBundle) -> str:
    """Return the bundle as a deterministic JSON string for storage."""
    return json.dumps(bundle.model_dump(), sort_keys=True, separators=(",", ":"))


def deserialize_bundle(payload: str | dict[str, Any]) -> CitizenshipBundle:
    """Inverse of :func:`serialize_bundle`. Validates structure."""
    if isinstance(payload, str):
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise IdentityError("CitizenshipBundle payload is not valid JSON") from exc
    else:
        data = payload
    try:
        return CitizenshipBundle.model_validate(data)
    except Exception as exc:
        raise IdentityError("CitizenshipBundle payload failed schema validation") from exc
