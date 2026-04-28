"""agno-dcp: cryptographic governance for Agno agents.

Public API surface. Imports all of the user-facing primitives into a
single namespace so callers can write::

    from agno_dcp import DCPAgent, PolicyEngine, MerkleAuditChain

without remembering submodule paths.
"""

from agno_dcp._version import __version__
from agno_dcp.agent import DCPAgent
from agno_dcp.audit.chain import (
    AuditEntry,
    AuditEvent,
    AuditEventType,
    MerkleAuditChain,
    RootSignature,
)
from agno_dcp.audit.exporter import ComplianceBundleExporter
from agno_dcp.audit.verifier import AuditChainVerifier, VerificationResult
from agno_dcp.exceptions import (
    AuditChainCorrupted,
    ConfigurationError,
    DCPAIError,
    IdentityError,
    MCPVerificationError,
    PolicyDenied,
    StorageError,
)
from agno_dcp.identity import (
    CitizenshipBundle,
    SecurityTier,
    deserialize_bundle,
    generate_citizenship_bundle,
    load_citizenship_bundle,
    serialize_bundle,
    verify_citizenship_bundle,
)
from agno_dcp.mcp.middleware import (
    DCPMCPMiddleware,
    MCPEnvelope,
    sign_mcp_message,
    verify_mcp_message,
)
from agno_dcp.policy.engine import PolicyEngine
from agno_dcp.policy.gate import IntentDeclaration, PolicyDecision, PolicyGate
from agno_dcp.policy.rules import RuleSet
from agno_dcp.storage.base import BaseStorage
from agno_dcp.storage.sqlite import SQLiteStorage
from agno_dcp.team import DCPTeam
from agno_dcp.workflow import DCPWorkflow

__all__ = [  # noqa: RUF022  (semantic groupings preferred over alphabetical)
    # version
    "__version__",
    # core wrappers
    "DCPAgent",
    "DCPTeam",
    "DCPWorkflow",
    # identity
    "CitizenshipBundle",
    "SecurityTier",
    "generate_citizenship_bundle",
    "load_citizenship_bundle",
    "verify_citizenship_bundle",
    "serialize_bundle",
    "deserialize_bundle",
    # policy
    "PolicyEngine",
    "PolicyGate",
    "PolicyDecision",
    "IntentDeclaration",
    "RuleSet",
    # audit
    "MerkleAuditChain",
    "AuditEvent",
    "AuditEventType",
    "AuditEntry",
    "RootSignature",
    "AuditChainVerifier",
    "VerificationResult",
    "ComplianceBundleExporter",
    # mcp
    "DCPMCPMiddleware",
    "MCPEnvelope",
    "sign_mcp_message",
    "verify_mcp_message",
    # storage
    "BaseStorage",
    "SQLiteStorage",
    # exceptions
    "DCPAIError",
    "PolicyDenied",
    "IdentityError",
    "AuditChainCorrupted",
    "ConfigurationError",
    "StorageError",
    "MCPVerificationError",
]


def __getattr__(name: str) -> object:
    """Lazy import for the optional Postgres backend."""
    if name == "PostgresStorage":
        from agno_dcp.storage.postgres import PostgresStorage

        return PostgresStorage
    raise AttributeError(f"module 'agno_dcp' has no attribute {name!r}")
