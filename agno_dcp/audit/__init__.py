"""Tamper-evident audit chain (DCP-03) for agno-dcp.

Public surface:

* :class:`MerkleAuditChain`: append-only chain that links every event
  to the previous one via SHA-256 and tracks a periodically-sealed
  Merkle root.
* :class:`AuditEvent`, :class:`AuditEventType`: event model and the
  closed enum of event categories.
* :class:`AuditEntry`: persisted record returned by ``append``.
* :class:`RootSignature`: signed Merkle root snapshot.
* :class:`ComplianceBundleExporter`: produces signed ZIP bundles for
  external auditors.
* :class:`AuditChainVerifier`: standalone verifier used by the CLI.
"""

from agno_dcp.audit.chain import (
    AuditEntry,
    AuditEvent,
    AuditEventType,
    MerkleAuditChain,
    RootSignature,
)
from agno_dcp.audit.exporter import ComplianceBundleExporter
from agno_dcp.audit.verifier import AuditChainVerifier, VerificationResult

__all__ = [
    "AuditChainVerifier",
    "AuditEntry",
    "AuditEvent",
    "AuditEventType",
    "ComplianceBundleExporter",
    "MerkleAuditChain",
    "RootSignature",
    "VerificationResult",
]
