# Tool security analysis

Per-tool breakdown of what each tool does, how it fails, and what stops it.
Three tools, three vulnerability classes, **one underlying bug**:

> An attacker-controlled string is placed into something that has structure — a
> filesystem path, a SQL statement, a network destination — and the string
> escapes the slot it was meant to occupy.

And one underlying defense:

> Never validate the request. Determine where it actually lands, and validate
> **that** — after any transformation that could change the answer.

---

## Threat context

The server runs as an ordinary process with the invoking user's full
permissions. Nothing sandboxes it. There is no container, no jail, no
permission prompt. Every boundary described below exists **only because
application code enforces it**.

Tool arguments originate from a language model, which can be influenced by
untrusted content in its context. Arguments are therefore treated as
attacker-controlled without exception.

---

## 1. `search_files` — path traversal

### Purpose

Read a file from the `sandbox/` directory and return its contents.

### Naive implementation

```python
SANDBOX = Path("sandbox")

def _read_sandboxed(query: str) -> str:
    return (SANDBOX / query).read_text()
```

Correct for well-formed input. `query="notes.txt"` resolves to
`sandbox/notes.txt` and returns its text.

### What the attacker controls

The entire `query` string, which becomes part of a filesystem path.

### Attack

**Relative traversal** — `query = "../../.ssh/id_rsa"`

```
sandbox/../../.ssh/id_rsa
  sandbox + ..       → /home/user/mcp-hardened
  mcp-hardened + ..  → /home/user
  + .ssh/id_rsa      → /home/user/.ssh/id_rsa
```

**Absolute path** — `query = "/etc/passwd"`

```python
Path("sandbox") / "/etc/passwd"    # → Path('/etc/passwd')
```

When the right-hand operand is absolute, `pathlib` **discards the left-hand
side entirely**. Same behaviour as `os.path.join`. The sandbox prefix
evaporates with no traversal sequence required.

**Symlink** — a link inside `sandbox/` pointing outward. Contains no `..`,
is not absolute, and still escapes.

### Worst case

Any file readable by the invoking user, returned into model context and
therefore off the machine: SSH private keys, `.env` files from other projects,
`~/.bash_history`, `~/.config/gh/hosts.yml` (GitHub tokens).

The asset being protected is not `sandbox/`. It is **everything adjacent to
it**.

### Insufficient defenses

```python
if ".." in query:            # /etc/passwd contains no ".."
    raise ValueError(...)     # symlinks contain no ".."
```

Blacklisting requires enumerating every hostile input. That is not a winnable
game.

### Defense

```python
SANDBOX = Path("sandbox").resolve()

def _read_sandboxed(query: str) -> str:
    target = (SANDBOX / query).resolve()
    if not target.is_relative_to(SANDBOX):
        raise ValueError("path escapes sandbox")
    if not target.is_file():
        raise ValueError("not a file")
    if target.stat().st_size > 100_000:
        raise ValueError("file too large")
    return target.read_text()
```

**Why it holds:**

- `.resolve()` collapses `..`, follows symlinks, and returns an absolute path.
  It yields the *real* destination rather than the requested one.
- `is_relative_to()` is an **allowlist on the destination**, not a blacklist on
  the input. Traversal, absolute paths, and symlinks all converge on the same
  question — "is the final location inside the permitted root?" — and all three
  fail it.
- **Order is the entire mechanism.** Checking before resolution lets
  `sandbox/../../.ssh/id_rsa` pass, because the raw string still appears to sit
  inside the sandbox. Only resolution reveals the true destination.
- The size cap is a **return-side** control. A legitimately-pathed 40 MB file
  flooding model context is its own failure mode.

### Not covered

- TOCTOU: a symlink created between `resolve()` and `read_text()`. Low risk in
  a single-user local process.
- Hard links inside the sandbox pointing to external inodes.

### Tests

```python
def test_traversal_rejected():
    with pytest.raises(ValueError):
        _read_sandboxed("../../.ssh/id_rsa")

def test_absolute_path_rejected():
    with pytest.raises(ValueError):
        _read_sandboxed("/etc/passwd")

def test_legitimate_read_succeeds():
    assert "internal note" in _read_sandboxed("notes.txt")
```

The third test is not optional. Hardening that breaks the legitimate case is
not hardening.

---

## 2. `query_records` — SQL injection

### Purpose

Return rows from a local SQLite database matching a category.

### Naive implementation

```python
def _query_records(filter: str) -> str:
    conn = sqlite3.connect("data/records.db")
    sql = f"SELECT * FROM records WHERE category = '{filter}'"
    return str(conn.execute(sql).fetchall())
```

### What the attacker controls

The entire `filter` string, which is concatenated directly into SQL source
text. The surrounding single quotes are the only thing separating their data
from the statement's grammar.

### Attack

**Predicate subversion** — `filter = "' OR '1'='1"`

```sql
SELECT * FROM records WHERE category = '' OR '1'='1'
```

The condition is unconditionally true. Every row returns.

**Schema disclosure** — `filter = "' UNION SELECT name, sql, null, null FROM sqlite_master --"`

Returns the full schema, enabling targeted follow-up queries against tables
this tool was never intended to expose.

**Not applicable here:** `'; DROP TABLE records; --` fails.
`sqlite3.Connection.execute()` rejects multiple statements and raises
`ProgrammingError`. (`executescript()` does not, which is why it must never
receive untrusted input.)

### Worst case

Read access to every row of every table in the database file. On SQLite via
`execute()`, the realistic impact is **exfiltration rather than destruction**.

### Insufficient defenses

Escaping quotes, stripping keywords, or regex filtering. All are blacklists
against a grammar with many equivalent encodings.

### Defense

```python
def _query_records(filter: str) -> str:
    conn = sqlite3.connect("file:data/records.db?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT id, name, category FROM records WHERE category = ? LIMIT 100",
        (filter,),
    ).fetchall()
    return "\n".join(str(r) for r in rows)
```

**Why it holds:**

Parameterization is **not escaping**. The database parses and compiles the
statement while `?` is still an unfilled hole in the parse tree. The value is
bound *after* compilation. It is structurally incapable of becoming syntax,
because the grammar was already fixed before the value existed.

Code and data travel in separate channels rather than being disambiguated after
the fact.

**Supporting controls:**

- `mode=ro` — read-only connection; writes fail at the driver level
- Explicit column list rather than `SELECT *` — no accidental disclosure when
  the schema grows
- `LIMIT 100` — return-side bound on context flooding

### Not covered

Placeholders bind **values only**, never identifiers. Dynamic table or column
names require a separate allowlist:

```python
if column not in {"name", "category"}:
    raise ValueError("column not permitted")
```

### Tests

```python
def test_tautology_rejected():
    result = _query_records("' OR '1'='1")
    assert "internal" not in result

def test_union_injection_rejected():
    result = _query_records("' UNION SELECT name, sql, null FROM sqlite_master --")
    assert "CREATE TABLE" not in result

def test_legitimate_query_succeeds():
    assert "widget" in _query_records("tools")
```

Note the assertion style: the hardened function does not raise on these inputs.
It treats them as a literal category string, matches nothing, and returns
empty. **Absence of leaked data is the pass condition.**

---

## 3. `fetch_doc` — SSRF

### Purpose

Fetch a documentation page and return its body text.

### Naive implementation

```python
def _fetch_doc(url: str) -> str:
    return httpx.get(url, follow_redirects=True).text
```

### What the attacker controls

The entire destination of an outbound request.

### Attack

No string manipulation is required. The vulnerability is **positional**: the
server sits inside a trust perimeter the attacker does not occupy.

| Target | Reachable by server, not by attacker |
|---|---|
| `http://localhost:8080` | Other local services |
| `http://192.168.1.1` | Router admin interfaces |
| `http://169.254.169.254/latest/meta-data/` | Cloud instance metadata — IAM credentials |
| `file:///etc/passwd` | Local filesystem, if the client supports the scheme |

SSRF does not exfiltrate a file. It **lends the attacker the server's network
position**.

### Worst case

Any HTTP-reachable service on localhost or the local network, including
services that assume network-level trust and implement no authentication of
their own. In cloud deployments, the metadata endpoint typically yields
credentials.

### Defense

```python
ALLOWED_HOSTS = {"docs.python.org", "example.com"}
MAX_REDIRECTS = 3

def _validate(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("https only")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not permitted")

def _fetch_doc(url: str) -> str:
    for _ in range(MAX_REDIRECTS):
        _validate(url)
        resp = httpx.get(url, follow_redirects=False, timeout=5)
        if resp.is_redirect:
            url = str(resp.next_request.url)
            continue
        return resp.text[:100_000]
    raise ValueError("too many redirects")
```

**Why it holds:**

An allowlist inverts the question from "is this destination hostile?" —
unanswerable — to "is this destination one of the small number I permit?"

**The redirect loop is the critical detail, and it is the same failure as
`search_files`.** Validating the supplied URL and then calling
`follow_redirects=True` checks the request rather than the destination. An
allowlisted host returning `302 → http://169.254.169.254/` defeats the check
entirely, because validation ran against a URL the client never actually
fetched.

Re-validating at every hop restores the invariant: **every request that is
actually issued has been checked.**

**Supporting controls:** explicit scheme allowlist (blocks `file://`,
`gopher://`), request timeout, response size cap.

### Not covered

**DNS rebinding.** An attacker controlling DNS for an allowlisted host can
resolve it to `127.0.0.1`. The hostname check passes; the connection reaches
localhost. Mitigation requires resolving the hostname, validating the resulting
IP against private ranges, and connecting to that IP directly — out of scope
for this project and documented in `THREAT_MODEL.md` as residual risk.

---

## Summary

| Tool | String becomes | Escapes into | Defense | Ordering requirement |
|---|---|---|---|---|
| `search_files` | filesystem path | entire home directory | resolve, then check against root | check **after** resolution |
| `query_records` | SQL grammar | every table in the file | parameterized binding | bind **after** compilation |
| `fetch_doc` | network destination | localhost and LAN | host allowlist | validate **every** hop |

Each defense shares the same structure: identify the true destination, compare
it against a small allowlist, and perform that comparison **after** any
transformation capable of changing the answer.
