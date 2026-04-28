# Architecture

`agno-dcp` is structured as four coordinated layers on top of the
Agno primitives. Each layer is independently testable, has a single
public class as its entry point, and persists into the same shared
storage so an external auditor sees a coherent ordering.

```
+---------------------------------------------------------------+
|  Application code (FastAPI, CLI, scheduled jobs, ...)         |
+---------------------------------------------------------------+
                       |
                       v
+---------------------------------------------------------------+
|  DCPAgent / DCPTeam / DCPWorkflow                             |
|  Subclass the Agno primitives.                                |
|                                                               |
|  pre_tool_call:                                               |
|    1. dcp_build_intent     (DCP-02)                           |
|    2. PolicyGate.evaluate  (DCP-02)                           |
|    3. on deny + strict     -> raise PolicyDenied              |
|                                                               |
|  run tool                                                     |
|                                                               |
|  post_tool_call:                                              |
|    append TOOL_EXECUTED to MerkleAuditChain (DCP-03)          |
+---------------------------------------------------------------+
        |                       |                  |
        v                       v                  v
   PolicyGate              PolicyEngine     MerkleAuditChain
   (signs intent           (evaluates       (hash chain
    + decision,             rules, signs    plus signed
    persists both)          decision)       Merkle roots)
                                                   |
                                                   v
                                         BaseStorage
                                  (SQLiteStorage / PostgresStorage)
                                                   |
                                                   v
                                         AuditChainVerifier  (offline)
                                         ComplianceBundleExporter
                                         (signed ZIP for auditors)

Optional fifth layer (DCP-04):

   DCPMCPMiddleware
   sign_outbound  -> envelope.dcp_*  added to MCP messages
   verify_inbound -> verify the envelope, fall back to plain MCP
                     when the peer does not speak DCP-AI
```

## Why subclasses, not adapters

The brief calls for cero cambios en Agno requeridos. Subclassing is
the pattern that achieves that without invasion: native users keep
their `Agent` import, DCP-AI users swap to `DCPAgent` and pass extra
kwargs. The Agno class is forwarded via `super().__init__(**kwargs)`,
so any future Agno additions land transparently.

When `agno` is not installed at import time, the wrapper subclasses a
lightweight stub. Tests run without Agno; production callers are
expected to install it.

## Where the cryptographic primitives live

`agno-dcp` does not implement signatures, hashes, or canonicalization.
Everything cryptographic is imported from the upstream
[`dcp-ai>=2.8.1`](https://pypi.org/project/dcp-ai/) Python SDK. That
ensures `agno-dcp` bundles are byte-exact compatible with verifiers
built on the SDK.

Imports are lazy: each layer's module imports the primitive on first
use, so the package loads even before `dcp-ai` is installed (helpful
in CI before deps are pinned). At runtime, missing primitives surface
as a clear :class:`agno_dcp.exceptions.IdentityError`.

## Storage shape

Five tables, all prefixed `dcp_*` to coexist with Agno's own tables in
the same database:

| Table                      | Purpose                                                   |
| -------------------------- | --------------------------------------------------------- |
| `dcp_citizenship_bundles`  | Persisted DCP-01 identity records, indexed by `agent_id`. |
| `dcp_intents`              | Signed Intent Declarations (DCP-02). Forensic queries.    |
| `dcp_policy_decisions`     | Signed allow/deny verdicts (DCP-02).                      |
| `dcp_audit_chain`          | Hash-chained audit log (DCP-03).                          |
| `dcp_audit_roots`          | Sealed Merkle roots, signed by the audit chain's keypair. |

The Postgres DDL is in `agno_dcp/storage/schema.sql` and is
idempotent. SQLite uses an analogous schema with the same column
names so applications can move between them without code changes.

## Hook semantics

Three hooks, all async:

* `dcp_pre_tool_call(tool_name, tool_args)` returns a
  :class:`PolicyDecision`. Raises :class:`PolicyDenied` in strict mode
  on deny. The recommended call site is the agent's `pre_tool_call`
  Agno hook. If Agno does not expose one yet, call it from your tool
  dispatcher instead, or use :meth:`DCPAgent.run_tool` which wraps the
  whole sequence.
* `dcp_post_tool_call(tool_name, tool_args, result, error=None)`
  appends a `TOOL_EXECUTED` audit event (and an `ERROR` event when
  `error` is set). Recommended call site: Agno's `post_tool_call`.
* `dcp_initialize()` runs once, lazily on first action. Creates
  storage tables and seals an `AGENT_CREATED` event.
