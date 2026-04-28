# Changelog

All notable changes to `agno-dcp` are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] (Unreleased)

Initial early-access release. Implements DCP-01 through DCP-04 over
the Agno primitives.

### Added

* `DCPAgent`, `DCPTeam`, `DCPWorkflow` wrappers that extend the Agno
  classes without requiring patches to Agno itself.
* `CitizenshipBundle` (DCP-01) generation, persistence, signature
  verification, and load helpers.
* Declarative YAML policy engine with signed verdicts (`PolicyEngine`,
  `PolicyGate`, `IntentDeclaration`, `PolicyDecision`).
* Hash-chained, Merkle-sealed audit log (`MerkleAuditChain`,
  `AuditEvent`, `AuditEventType`, `RootSignature`).
* `AuditChainVerifier` and the `agno-dcp verify` CLI for offline
  integrity checks.
* `ComplianceBundleExporter` producing signed ZIP archives.
* DCP-AI envelope for outbound and inbound MCP messages
  (`DCPMCPMiddleware`, `sign_mcp_message`, `verify_mcp_message`).
* Storage backends: `SQLiteStorage` (in-process, zero extra deps) and
  `PostgresStorage` (SQLAlchemy 2 async, optional `[postgres]` extra).
* Compliance mappings for EU AI Act (Articles 12, 13, 14, 15, 50) and
  NIST AI RMF (Govern, Map, Measure, Manage).
* End-to-end integration test exercising agent + policy + audit +
  verifier + exporter.

### Notes

* Peer dependency on `agno>=2.0.0` is declared but not enforced at
  import time. The wrappers fall back to a lightweight stub when
  Agno is absent so unit tests can run in isolation.
* Cryptographic primitives are imported from `dcp-ai>=2.8.1` (the
  reference Python SDK). Bundles produced here are byte-exact
  compatible with verifiers built on that SDK.
