# Examples

End-to-end demos arrive in `v0.2.0`.

The library API is stable enough that you can already build your own:
start from the README quickstart, replace the toy `crm_lookup` with
your real tools, and point `MerkleAuditChain` at your real database.

The reference end-to-end demo we are planning includes:

* A collections agent that looks up customers, proposes payment
  plans, and emails confirmations.
* A team of two agents (collections + risk) coordinated by `DCPTeam`.
* A workflow that escalates flagged cases through `DCPWorkflow`.
* A FastAPI service exposing all of the above behind DCP-AI-signed
  request handlers.
* A working Compliance Bundle for a fake auditor to verify offline.

If you build something with `agno-dcp` before that ships, open an
issue. We may include it as an example.
