# MCP-HARDENED

A deliberately small MCP server built to demonstrate security hardening
against the OWASP MCP Top 10, with a test suite that proves the defenses hold.

## Status

**In progress.** Day 1 of 7 — scaffold and transport smoke test only.

## Warning

Early commits contain **intentionally vulnerable** implementations. The build
order is deliberate: write the naive version, write attack tests that prove the
vulnerability is reachable, then harden until the tests pass. A security test
that has never failed is not a test.

Do not use any commit from this repo as a reference implementation until the
hardening commits land.

## Planned scope

Three read-only tools, each hosting one vulnerability class:

| Tool | Vulnerability class | Defense |
|---|---|---|
| `search_files` | Path traversal | Resolve path, assert inside sandbox root |
| `query_records` | SQL injection | Parameterized queries only |
| `fetch_doc` | SSRF | Domain allowlist, revalidated after redirects |

Plus audit logging of every tool call and its arguments.

## Explicitly out of scope

- **Prompt injection** — unsolved industry-wide, not attempting
- **Tool poisoning** — a consuming-side threat; a server cannot prevent a client
  from connecting to a poisoned server
- Multi-user authentication, rate limiting

## Stack

Python 3.12 · FastMCP 3.3.1 · pytest · stdio transport
