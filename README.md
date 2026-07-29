# MCP-HARDENED

A deliberately small MCP server built to demonstrate security hardening
against the OWASP MCP Top 10, with a test suite that proves the defenses hold.

## Status

**In progress.** Stage 3 of 7 — 3 working tools that are vulnerable to exploitation on purpose.

## Warning

Early commits contain **intentionally vulnerable** implementations. The build
order is deliberate: write the naive version, write attack tests that prove the
vulnerability is reachable, then harden until the tests pass. A security test
that has never failed is not a test.

Do not use any commit from this repo as a reference implementation until the
hardening commits land.

## ***WARNING***
# mcp-hardened

> **This repository contains intentionally vulnerable code.**
> Commits tagged `naive-baseline` and earlier implement path traversal, SQL
> injection, and SSRF **on purpose**, as the "before" half of a security
> demonstration. Do not use any code from this repository as a reference
> implementation, and do not deploy it. It is a teaching artifact, not a
> library.

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
