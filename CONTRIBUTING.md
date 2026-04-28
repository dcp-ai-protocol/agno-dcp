# Contributing to agno-dcp

Thanks for considering a contribution. The project is small and
opinionated; the rules below keep iteration fast and reviews short.

## Ground rules

* **One concern per PR.** A bug fix and a refactor are two PRs.
* **Tests for every change.** New behaviour ships with new tests.
  Bug fixes ship with a regression test.
* **Type hints on every public function.** `mypy --strict` must
  pass.
* **No silent except blocks.** Use the typed exceptions in
  [`agno_dcp/exceptions.py`](agno_dcp/exceptions.py) or add a new
  one with a clear semantic.
* **No em dashes or en dashes** in code, comments, docs, or commit
  messages. Use commas, parentheses, periods, or colons.
* **English only.** All committed text in English regardless of the
  contributor's locale.

## Local setup

```bash
git clone https://github.com/dcp-ai-protocol/agno-dcp.git
cd agno-dcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,postgres]"
pre-commit install
```

## Running checks

```bash
ruff check .
ruff format --check .
mypy agno_dcp/
pytest -ra
pytest --cov=agno_dcp --cov-report=term-missing
```

## Commit conventions

[Conventional Commits](https://www.conventionalcommits.org/) with the
following scopes: `core`, `agent`, `team`, `workflow`, `identity`,
`policy`, `audit`, `mcp`, `storage`, `compliance`, `docs`, `ci`,
`tests`.

Examples:

```
feat(policy): support payload.* in dotted-path matchers
fix(audit): recompute prev_hash on out-of-order inserts
docs(why): clarify when not to adopt agno-dcp
```

## Reporting security issues

Do not open a public issue for security reports. Email
`security@dcp-ai.org` instead. We aim to acknowledge within 48 hours.

## Code of Conduct

The project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be kind, technical, and direct.
