# Benchmarks

This page is a placeholder. Numbers will be filled in once we have a
representative workload.

## Methodology (planned)

* Compare a vanilla Agno agent against the same agent wrapped in
  `DCPAgent`, on the same sequence of tool calls.
* Storage backend: SQLite in-memory and Postgres on localhost.
* Iterations: 10,000 tool calls per scenario, p50, p95, and p99
  latency reported.
* Repeat under permissive policy and under deny-by-default policy
  with one matching allow rule.

## Provisional results

| Operation                              | Agno alone | Agno + agno-dcp | Overhead |
| -------------------------------------- | ---------- | --------------- | -------- |
| Construct agent                        | TODO       | TODO            | TODO     |
| Pre-tool gate (intent + decision)      | TODO       | TODO            | TODO     |
| Append audit entry                     | TODO       | TODO            | TODO     |
| Seal Merkle root (1k entries)          | n/a        | TODO            | n/a      |
| Compliance Bundle export (1k entries)  | n/a        | TODO            | n/a      |

## Goals

* Pre-tool gate cost under 5 ms p95 with embedded engine and SQLite.
* Audit append cost under 2 ms p95 with embedded SQLite.
* Postgres backend: pre-tool gate under 10 ms p95 on a co-located
  database.

We will publish numbers once the v0.2.0 demo is complete; the demo
exercises a realistic workload (multi-step collections agent) on
both backends.
