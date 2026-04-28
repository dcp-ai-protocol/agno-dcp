"""Exception hierarchy for agno-dcp.

Every error raised by the library inherits from :class:`DCPAIError` so
callers can ``except DCPAIError`` as a single broad guard. The specific
subclasses let callers branch on category (policy denial, identity
problem, audit corruption, storage failure).
"""

from __future__ import annotations

from typing import Any


class DCPAIError(Exception):
    """Base class for every error raised by agno-dcp.

    All library exceptions inherit from this. Catch this class to opt
    out of all DCP-AI failure modes at once.
    """


class IdentityError(DCPAIError):
    """Raised when a Citizenship Bundle cannot be created, loaded, or
    verified.

    Common causes: missing keypair material, corrupted bundle JSON,
    signature verification failure, mismatched agent identifiers.
    """


class PolicyDenied(DCPAIError):  # noqa: N818  (name fixed by brief)
    """Raised in strict mode when the PolicyGate refuses an action.

    The ``decision`` attribute carries the full
    :class:`~agno_dcp.policy.gate.PolicyDecision` so callers can log or
    re-emit it. The ``intent`` attribute carries the
    :class:`~agno_dcp.policy.gate.IntentDeclaration` that was rejected.

    Args:
        message: Human readable reason for the deny. Usually mirrors
            ``decision.reason``.
        intent: The intent that was rejected.
        decision: The full decision record.
    """

    def __init__(
        self,
        message: str,
        *,
        intent: Any | None = None,
        decision: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.intent = intent
        self.decision = decision


class AuditChainCorrupted(DCPAIError):  # noqa: N818  (name fixed by brief)
    """Raised when the Merkle audit chain fails an integrity check.

    The ``entry_index`` attribute, when set, identifies the first entry
    where the recomputed hash diverged from the stored hash.
    """

    def __init__(self, message: str, *, entry_index: int | None = None) -> None:
        super().__init__(message)
        self.entry_index = entry_index


class StorageError(DCPAIError):
    """Raised on any persistence layer failure (Postgres or SQLite).

    Includes connection drops, schema mismatches, and constraint
    violations bubbled up from the database driver.
    """


class ConfigurationError(DCPAIError):
    """Raised when the library is configured with values that cannot
    work together.

    Examples: empty policy ruleset combined with ``default: deny``,
    storage URL that does not match the storage class, missing required
    environment variables in strict mode.
    """


class MCPVerificationError(DCPAIError):
    """Raised when an inbound MCP message fails signature verification.

    The original message payload is attached as ``message`` for
    forensic logging.
    """

    def __init__(self, reason: str, *, message: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.message = message
