# Why agno-dcp

## The problem

Agno gives you the runtime: fast, private, production-ready, with the
ergonomics most teams want when they pick a Python agent framework.
What it does not give you (and is not in scope for the project today)
is cryptographic governance.

For most use cases that is fine. For one use case it is not: when you
sell agentic systems to regulated buyers, banks, healthcare,
government, energy, the question on the table moves from "does the
agent work" to "can you prove what it did, who is responsible, and
that nothing was tampered with after the fact." Those buyers have a
checklist. Today the checklist either disqualifies your stack or
forces you to ship custom plumbing for every deal.

What that custom plumbing always boils down to:

* A cryptographic identity per agent that ties back to a named
  responsible human.
* A policy gate that records, before each action, what the agent
  declared it was about to do and what verdict the engine returned.
* An audit trail that an external auditor can verify without trusting
  the live system.
* Inter-agent message signing for cross-organisation trust.
* A mapping to the regulator's framework of choice (EU AI Act, NIST AI
  RMF, sector-specific regimes).

`agno-dcp` is that plumbing, factored out, opinionated, and reusable.
The library does not replace anything in Agno. You import
`DCPAgent` instead of `Agent`, you pass `dcp_human_principal=...`,
and you gain the five capabilities above. If DCP-AI is not active,
the agent runs identically to a plain Agno agent.

## The solution

`agno-dcp` wires four DCP-AI specifications onto the Agno primitives:

* **DCP-01 (Identity & Principal Binding).** Every agent gets a
  Citizenship Bundle: an Ed25519 public key bound to a responsible
  human, self-signed at creation, persisted with the rest of the
  agent's state.
* **DCP-02 (Intent Declaration & Policy Gating).** Before each tool
  call (and team message, and MCP message, and workflow step), the
  agent emits a signed Intent Declaration. A pluggable Policy Engine
  returns a signed allow/deny verdict. Both records survive the
  request lifecycle.
* **DCP-03 (Audit Chain & Transparency).** Every event is appended to
  a hash-chained log. The chain root is periodically signed and
  persisted. An external auditor can recompute the root from the
  stored entries and confirm nothing has changed.
* **DCP-04 (Agent-to-Agent Communication).** Outbound MCP messages
  carry a signed envelope. Inbound MCP messages are verified against
  the embedded public key, with explicit fallback to the standard Agno
  flow when the peer does not speak DCP-AI.

The cryptographic primitives are imported from the upstream DCP-AI
Python SDK, not re-implemented here. Bundles produced by `agno-dcp`
are byte-exact compatible with verifiers built on the SDK.

## When to use it

* You sell to regulated buyers and the deal blocks on traceability or
  accountability questions.
* You are deploying agents that will execute actions with consequences
  (payments, account changes, customer communications) and your
  internal audit team needs more than application logs.
* You are pursuing or maintaining an EU AI Act or NIST AI RMF
  compliance posture and want concrete artefacts to point at.

## When not to use it

* You are still in PoC / prototype mode and the agent does nothing
  with real-world side effects. The DCP-AI overhead is small but
  non-zero, and the operational benefit only appears when you have
  actions worth governing.
* Your deployment is fully internal and you trust the surrounding
  infrastructure (logs, JWT, RBAC) to satisfy your audit needs.
* You need governance only at the LLM layer (model output filtering,
  prompt classification). `agno-dcp` operates at the action layer and
  intentionally does not opine on what the model says, only on what
  the agent does as a result.
