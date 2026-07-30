# MCP-HARDENED

A deliberately small MCP server built to demonstrate security hardening
against the OWASP MCP Top 10, with a test suite that proves the defenses hold.

## Warning

> **This repository contains intentionally vulnerable code.** Commits at and
> before the `naive-baseline` tag implement path traversal, SQL injection, and
> SSRF **on purpose** — they are the "before" half of a security demonstration.
> The build order is deliberate: write the naive version, write attack tests
> that prove the vulnerability is reachable, then harden until the tests pass.
> Do not use any code from this repository as a reference implementation, and do not deploy it. This is
> a teaching artifact, not a library.

Ongoing project. Things may change.

## What this demonstrates

Three read-only tools, each hosting one vulnerability class:

| Tool | Vulnerability class | Defense |
|---|---|---|
| `search_files` | Path traversal | Resolve path, assert inside sandbox root |
| `query_records` | SQL injection | Parameterized queries only |
| `fetch_doc` | SSRF | Host allowlist, revalidated after redirects |

Full breakdown of each tool in [docs/TOOLS.md](docs/TOOLS.md).

## Before and after

The same test suite, run against the naive implementation and against the
hardened one:

- [`docs/attack-suite-before.txt`](docs/attack-suite-before.txt) — attack
  tests failing, functional tests passing
- [`docs/attack-suite-after.txt`](docs/attack-suite-after.txt) — everything
  passing

The hardening itself, as a diff:
[`naive-baseline...master`](https://github.com/Nu1lstep/MCP-Hardened/compare/naive-baseline...master)

## Explicitly out of scope

- **Prompt injection** — unsolved industry-wide, not attempting
- **Tool poisoning** — a consuming-side threat; a server cannot prevent a client
  from connecting to a poisoned server
- **DNS rebinding** — the host allowlist checks the name, not the resolved IP
- Multi-user authentication, rate limiting

## OWASP MCP Top 10 coverage

| ID | Item | Status |
|---|---|---|
| MCP01 | Token mismanagement / secret exposure | Addressed |
| MCP02 | Privilege escalation via scope creep | Addressed |
| MCP03 | Tool poisoning | Not addressable at the server layer |
| MCP04 | Supply chain | Partially addressed |
| MCP05 | Command injection | Addressed — the focus of this project |
| MCP06 | Intent flow subversion | Not addressable at the server layer |
| MCP07 | Insufficient authentication / authorization | Out of scope for this architecture |
| MCP08 | Lack of audit and telemetry | Designed, not implemented |
| MCP09 | Shadow servers | Not addressable at the server layer |
| MCP10 | Context injection / over-sharing | Addressed |

Full reasoning per item in [docs/OWASP-MCP-COVERAGE.md](docs/OWASP-MCP-COVERAGE.md)

## Stack

Python 3.12 · FastMCP 3.3.1 · pytest · SQLite · stdio transport

## Running it

```bash
uv sync
uv run scripts/seed_db.py     # creates data/records.db, needed by query_records
uv run pytest -v
```

To poke at the tools by hand:

```bash
npx @modelcontextprotocol/inspector uv run src/server.py
```

## Attribution

Built with Claude Code. The implementation, threat model, and documentation in
this repository were AI-generated.

My contribution was direction and review: setting the scope, deciding what
stays out of scope, approving or rejecting each step, and verifying behavior in
the MCP Inspector at each stage.

