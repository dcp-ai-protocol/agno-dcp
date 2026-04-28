# API reference

The full public surface lives at the top of `agno_dcp/__init__.py`.
Everything else is internal and may change without notice.

## Agent / Team / Workflow

| Class               | Module                | Notes                                                       |
| ------------------- | --------------------- | ----------------------------------------------------------- |
| `DCPAgent`          | `agno_dcp.agent`      | Subclasses `agno.agent.Agent`. Adds DCP-AI hooks and state. |
| `DCPTeam`           | `agno_dcp.team`       | Subclasses `agno.team.Team`. Team-level identity + audit.   |
| `DCPWorkflow`       | `agno_dcp.workflow`   | Subclasses `agno.workflow.Workflow`. Per-step audit.        |

## Identity (DCP-01)

| Symbol                                | Returns                                       |
| ------------------------------------- | --------------------------------------------- |
| `CitizenshipBundle`                   | Pydantic model, the identity record.          |
| `SecurityTier`                        | `Literal["tier-1","tier-2","tier-3","tier-4"]`. |
| `generate_citizenship_bundle(...)`    | `tuple[CitizenshipBundle, secret_key_b64]`.   |
| `load_citizenship_bundle(id, store)`  | `CitizenshipBundle` (signature-verified).     |
| `verify_citizenship_bundle(bundle)`   | `bool`.                                       |
| `serialize_bundle(bundle)`            | `str` (deterministic JSON).                   |
| `deserialize_bundle(payload)`         | `CitizenshipBundle`.                          |

## Policy (DCP-02)

| Symbol                                | Returns                                       |
| ------------------------------------- | --------------------------------------------- |
| `IntentDeclaration.create(...)`       | Signed `IntentDeclaration`.                   |
| `IntentDeclaration.verify()`          | `bool`.                                       |
| `PolicyDecision`                      | Pydantic model, signed verdict.               |
| `PolicyEngine.from_yaml(path)`        | Build from YAML file.                         |
| `PolicyEngine.from_dict(data)`        | Build from in-memory dict.                    |
| `PolicyEngine.permissive()`           | Default-allow engine.                         |
| `PolicyEngine.from_external(...)`     | Reserved for v0.2.0 (raises NotImplementedError). |
| `PolicyEngine.evaluate(intent, tier)` | `PolicyDecision`.                             |
| `PolicyEngine.verify_decision(d)`     | `bool`.                                       |
| `PolicyGate(engine, chain, strict)`   | Combines all of the above + audit emission.   |
| `PolicyGate.evaluate(intent, tier)`   | `PolicyDecision`. Raises `PolicyDenied` in strict. |
| `RuleSet`                             | Pydantic model, the parsed YAML schema.       |

## Audit (DCP-03)

| Symbol                                  | Returns                                     |
| --------------------------------------- | ------------------------------------------- |
| `AuditEvent`                            | Pydantic model, input to `append`.          |
| `AuditEventType`                        | Closed enum of event categories.            |
| `AuditEntry`                            | Persisted record returned by `append`.      |
| `RootSignature`                         | Signed Merkle root snapshot.                |
| `MerkleAuditChain.append(event)`        | `AuditEntry`.                               |
| `MerkleAuditChain.seal_root(agent_id?)` | `RootSignature`.                            |
| `MerkleAuditChain.verify_range(...)`    | `bool`. Raises `AuditChainCorrupted`.       |
| `MerkleAuditChain.verify_root_signature(root)` | `bool`.                              |
| `AuditChainVerifier.verify(...)`        | `VerificationResult`.                       |
| `ComplianceBundleExporter.export(...)`  | `Path` to the signed ZIP.                   |

## MCP (DCP-04)

| Symbol                                    | Returns                                   |
| ----------------------------------------- | ----------------------------------------- |
| `sign_mcp_message(msg, sk, pk)`           | `dict` with envelope appended.            |
| `verify_mcp_message(msg)`                 | `bool`.                                   |
| `has_envelope(msg)`                       | `bool`.                                   |
| `DCPMCPMiddleware.sign_outbound(msg)`     | Wrapped `dict`, plus audit event.         |
| `DCPMCPMiddleware.verify_inbound(msg)`    | Stripped `dict`, `None`, or raises.       |

## Storage

| Symbol                              | Notes                                            |
| ----------------------------------- | ------------------------------------------------ |
| `BaseStorage`                       | Abstract contract.                               |
| `SQLiteStorage(path)`               | File or `:memory:`. No extra deps.               |
| `PostgresStorage(database_url)`     | Requires the `[postgres]` extra.                 |

## Exceptions

| Class                  | Raised when ...                                       |
| ---------------------- | ------------------------------------------------------ |
| `DCPAIError`           | Base class. Catch this to opt out of all DCP failures. |
| `IdentityError`        | Citizenship Bundle creation, load, or verify fails.    |
| `PolicyDenied`         | Strict-mode deny. Carries `intent` and `decision`.     |
| `AuditChainCorrupted`  | Chain integrity check fails. Carries `entry_index`.    |
| `StorageError`         | Persistence layer failure.                             |
| `ConfigurationError`   | Library misconfiguration at construction.              |
| `MCPVerificationError` | Strict-inbound MCP signature failure.                  |
