# OWASP MCP Top 10 — Coverage Analysis

Where this server sits against each item in the OWASP MCP Top 10, and the
reasoning behind the items it does not address.

> The OWASP MCP Top 10 is in beta as of 2026. Item numbering and scope may
> change.

> **Attribution.** This project was built with Claude Code. The implementation
> and documentation are AI-generated. My contribution was direction and
> review — setting scope, deciding what stays out of scope, approving each
> step, and verifying behavior in the MCP Inspector. See the README for detail.

---

## Summary

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

Four addressed, one designed but not built, one partial, one out of scope for
this architecture, and three that sit outside a server's control boundary.

---

## Threat model context

This server runs over stdio transport, locally, for a single user. It is
launched as a child process by an MCP client and communicates over stdin and
stdout. There is no network listener, no multi-tenancy, and no authentication
surface.

It runs with the invoking user's full permissions. Nothing sandboxes it — no
container, no jail, no permission prompt. Every boundary described below exists
because application code enforces it.

Tool arguments originate from a language model whose context may contain
untrusted content, so arguments are treated as attacker-controlled throughout.

---

## Addressed

### MCP01 — Token mismanagement / secret exposure

**Threat.** Credentials embedded in configuration, committed to source control,
or written to logs. GitGuardian found 24,008 unique secrets in MCP-related
configs on public GitHub, 2,117 of them still valid at scan time.

**This server.** No credentials are held — all three tools read local resources
or public HTTPS. Where secrets would be required, the pattern is environment
variables only, never configuration files, and never written to the audit log.
`.env` is gitignored.

Seed data uses a deliberately scanner-safe placeholder rather than a realistic
key prefix, so the repository does not trip secret scanning.

### MCP02 — Privilege escalation via scope creep

**Threat.** A tool acquires broader capability than its purpose requires, so a
successful injection inherits more authority than it should.

**This server.** All tools are read-only. No writes, no deletes, no shell
execution, no filesystem mutation. The database connection opens in read-only
mode (`mode=ro`), so writes fail at the driver level rather than relying on
application logic.

Tool annotations declare `readOnlyHint: true` and `destructiveHint: false`,
with `openWorldHint` set per tool so a client can distinguish local-resource
tools from the one that reaches the internet.

Annotations are hints rather than enforcement — a client may ignore them, and a
malicious server may declare them falsely. They are noted under residual risk
for that reason.

### MCP05 — Command injection

**Threat.** Attacker-controlled input placed into something with structure — a
filesystem path, a SQL statement, a network destination — escaping the slot it
was meant to occupy. Endor Labs found 82% of 2,614 analyzed MCP implementations
use file operations prone to path traversal, and 67% use APIs related to code
injection.

**This server.** This is the focus of the project. Three tools, three injection
classes, each with a naive implementation, an attack test proving the
vulnerability is reachable, and a hardening commit that turns the test green.

| Tool | Class | Defense |
|---|---|---|
| `search_files` | Path traversal | Resolve, then verify containment within the sandbox root |
| `query_records` | SQL injection | Parameterized binding — values cannot become grammar |
| `fetch_doc` | SSRF | Host allowlist, revalidated on every redirect hop |

Full per-tool analysis in [`TOOLS.md`](TOOLS.md).

The pattern shared across all three: validate the destination rather than the
request, and do so after any transformation that could change the answer. A
path is checked after resolution, not before. A URL is checked at every
redirect hop, not once on the URL supplied.

### MCP10 — Context injection / over-sharing

**Threat.** A tool returns more data than the caller needs, and it enters model
context — and therefore leaves the machine — regardless of whether any
vulnerability was exploited. A legitimately-pathed 40 MB file is a leak even
though nothing was attacked.

**This server.** Return-side bounds on every tool: a file size cap on
`search_files`, `LIMIT` and an explicit column list rather than `SELECT *` on
`query_records`, and response truncation on `fetch_doc`.

Explicit column selection also means a future schema addition does not silently
begin disclosing a new field.

---

## Designed, not implemented

### MCP08 — Lack of audit and telemetry

**Threat.** No record of which tool was invoked with which arguments, so an
incident cannot be reconstructed.

**Design.** Every tool invocation logged with timestamp, tool
name, and the arguments received. Rejections logged with the reason, so a
blocked traversal attempt is visible rather than silent.

The log would be a local file writable by the same user that runs the server,
which is a meaningful limitation — noted under residual risk.

---

## Partially addressed

### MCP04 — Supply chain

**Threat.** A dependency, or an MCP server itself, is malicious or compromised.
The first publicly documented malicious MCP server (`postmark-mcp`) reached
roughly 1,500 downloads per week and 300 organizations before disclosure.

**This server.** Dependencies are pinned to exact versions with a committed
lock file, and the dependency surface is deliberately small — `fastmcp` and
`httpx`, with `sqlite3` and `pathlib` from the standard library.

**Why partial.** Supply chain security is largely a process control rather than
a code control. Pinning and lock files raise the cost of a silent substitution
but do not detect a compromised upstream. Fuller coverage would involve
signature verification, SBOM generation, and continuous dependency scanning —
practices that sit at the organizational level rather than inside a single
server.

---

## Out of scope for this architecture

### MCP07 — Insufficient authentication / authorization

**Threat.** A server exposes tools without verifying caller identity or
enforcing per-caller permissions.

**Why out of scope.** This server communicates over stdio as a child process of
a single local client. There is no network listener and no second caller.
Authentication has no surface to protect here: any process able to spawn this
server already runs with the user's permissions and could read the same files
directly.

The item becomes relevant under HTTP transport with multiple users, where it
calls for OAuth 2.1 with per-request scope validation. That is a different
deployment model rather than an extension of this one.

---

## Not addressable at the server layer

These three describe threats that sit outside a server's control boundary.

### MCP03 — Tool poisoning

**Threat.** Malicious instructions embedded in tool metadata. Invariant Labs
demonstrated in April 2025 that hidden text in a tool description enters the
agent's context as trusted content. The poisoned tool does not need to be
called — being loaded into context is sufficient. OWASP rates this Critical
(DREAD 46.5/50), with sub-techniques including rug pulls, schema poisoning, and
tool shadowing.

**Why a server cannot address it.** Tool poisoning is a threat to the consuming
side. This server's descriptions state plainly what each tool does and contain
no hidden instructions, but that is honesty rather than defense — nothing it
does prevents a client from also connecting to a poisoned server.

The mitigations that work are client-side: pinning tool descriptions and
alerting on change, server allowlisting, and treating `tools/list` output as
untrusted input.

A server can avoid being the attacker. It cannot act as the defense.

### MCP06 — Intent flow subversion

**Threat.** The agent is manipulated into invoking legitimate tools in a
harmful sequence, or with harmful arguments, through injected content anywhere
in its context.

**Why a server cannot address it.** This is the prompt injection family, which
remains unsolved. The problem has been public for over two and a half years
without a convincing general mitigation. The relevant framing is the "lethal
trifecta" — private data, untrusted instructions, and an exfiltration vector in
the same context — and MCP makes assembling all three straightforward.

From the server's position, a subverted call is indistinguishable from a
legitimate one: correct tool, well-formed arguments, valid permissions. Every
individual call may be legal while the sequence is hostile.

The partial mitigations available are architectural rather than
implementational: human-in-the-loop approval for consequential operations,
capability separation so no single agent context holds all three legs of the
trifecta, and limiting the blast radius of individual tools. This server does
the last of these — read-only tools with bounded outputs — which reduces impact
without addressing cause.

### MCP09 — Shadow servers

**Threat.** Unauthorized or unregistered MCP servers running in an environment,
invisible to security review.

**Why a server cannot address it.** This is a fleet governance problem.
Detection requires an inventory of what is installed across an environment,
comparison against an approved list, and enforcement at the client or
endpoint — none of which is visible from inside a single server process. A
shadow server is by definition one nobody configured, so it cannot be asked to
report itself.

---

## Residual risk

What remains exposed after everything above.

**Prompt injection.** Unsolved. The agent can be manipulated into calling
legitimate tools in harmful sequences. Read-only tools bound the impact but do
not prevent it.

**Annotations are advisory.** `readOnlyHint` and `destructiveHint` are
declarative metadata. A client may ignore them, and a malicious server may
declare them falsely. They inform client behavior rather than enforcing
anything.

**The audit log would not be tamper-evident.** A local file writable by the same
user that runs the server can be edited by anyone with that user's permissions.
Tamper-evidence would require append-only storage or remote shipping.

**DNS rebinding defeats the host allowlist.** An attacker controlling DNS for
an allowlisted host can resolve it to a private address. The hostname check
passes and the connection reaches localhost. Mitigation would require resolving
the hostname, validating the resulting IP against private ranges, and
connecting to that address directly.

**TOCTOU on path resolution.** A symlink created between `resolve()` and
`read_text()` would defeat containment. Low risk in a single-user local
process, non-zero in principle.

**Host compromise defeats everything.** Every control here assumes the machine
is not already controlled by an attacker.

---

## Sources

- OWASP MCP Top 10 (beta, 2026)
- Invariant Labs — tool poisoning disclosure, April 2025
- Endor Labs — MCP implementation scan, 2,614 servers
- GitGuardian — secrets in public MCP configurations

Scan figures across published MCP security research vary considerably by
methodology; one independent audit found roughly a 78% false-positive rate from
YARA-based MCP scanners. Figures cited here are directional rather than
precise.
