import functools
import inspect
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urljoin

import httpx
from fastmcp import FastMCP

mcp = FastMCP("hardened-demo")

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = (ROOT / "sandbox").resolve()
DB_PATH = ROOT / "data" / "records.db"

# Read at call time rather than captured at import, so tests can redirect the
# log without touching the real logs/ directory. The directory is created on
# first write, not on import.
AUDIT_LOG_PATH = ROOT / "logs" / "audit.jsonl"

MAX_FILE_BYTES = 100_000

# Illustrative allowlist for the demo — replace with real documentation
# hosts before any actual use.
ALLOWED_HOSTS = frozenset({"example.com", "www.example.com"})
MAX_REDIRECTS = 3
FETCH_TIMEOUT_SECONDS = 5.0
MAX_BODY_BYTES = 100_000

LOCAL_READONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

OPEN_READONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def _write_audit_entry(entry: dict) -> None:
    """Append one JSON Lines record to the audit log.

    Deliberately does NOT use the logging module. Under stdio transport stdout
    carries JSON-RPC, and any library calling logging.basicConfig() can attach a
    stdout StreamHandler to the root logger, which propagation would then use to
    corrupt the protocol. A direct append has no global state to hijack.

    Writes fail open: a full or unwritable disk loses the entry rather than
    halting the server. The failure goes to stderr, which is safe here because
    only stdout carries protocol traffic.
    """
    try:
        path = AUDIT_LOG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        # json.dumps escapes newlines, so an argument containing "\n" cannot
        # forge a second log entry. The format is the log-injection defense.
        line = json.dumps(entry, default=str)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception as exc:  # noqa: BLE001 - audit must never break a call
        try:
            print(f"audit: failed to write entry: {exc}", file=sys.stderr)
        except Exception:  # noqa: BLE001 - stderr failure must not propagate
            pass


def audit(fn):
    """Record every invocation of a tool to the audit log.

    Applied to the @mcp.tool functions rather than the _helpers: the log records
    tool invocations, and a direct helper call is not one.

    functools.wraps is load-bearing. FastMCP builds its JSON schema from
    __annotations__, the signature, and __doc__ — without wraps the tool would
    register with an empty schema and no description.

    Arguments are logged verbatim, including hostile ones: for these tools the
    argument IS the attack payload, which is the thing worth seeing. Anything
    consuming this log must treat those fields as untrusted text.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        bound = inspect.signature(fn).bind(*args, **kwargs)
        bound.apply_defaults()

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": fn.__name__,
            "arguments": dict(bound.arguments),
        }

        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            entry["outcome"] = "rejected"
            entry["error"] = str(exc)
            _write_audit_entry(entry)
            # Re-raise: swallowing here would defeat every rejection path.
            raise

        entry["outcome"] = "ok"
        # Length only, never the value. A successful search_files can return
        # 100KB, and logging content would reintroduce the over-sharing problem
        # that the return-side caps exist to prevent.
        entry["result_len"] = len(result) if isinstance(result, str) else None
        _write_audit_entry(entry)
        return result

    return wrapper


def _read_sandboxed(query: str) -> str:
    # Resolve first, THEN check containment. Checking the raw string before
    # resolution lets "../OUTSIDE_SANDBOX.txt" through, because the unresolved
    # path still carries the sandbox prefix. Note that SANDBOX / "/etc/passwd"
    # discards the sandbox entirely under pathlib's absolute-path semantics,
    # which the post-resolution check below also catches.
    path = (SANDBOX / query).resolve()

    if path != SANDBOX and SANDBOX not in path.parents:
        raise ValueError("path escapes the sandbox root")

    if not path.is_file():
        raise ValueError("not a regular file")

    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES} byte limit")

    return path.read_text()


def _query_records(filter: str) -> str:
    # Read-only connection plus a bound parameter. Injection input is never
    # parsed as SQL here: it becomes a literal category string that matches
    # nothing, so the caller gets an empty result rather than an error.
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        cursor = conn.cursor()
        sql = (
            "SELECT id, name, category, note FROM records "
            "WHERE category = ? LIMIT 100"
        )
        rows = cursor.execute(sql, (filter,)).fetchall()
    finally:
        conn.close()
    if not rows:
        return "No matching records."
    return "\n".join(
        f"[{row[0]}] {row[1]} ({row[2]}): {row[3]}" for row in rows
    )


# Host allowlist validates the hostname, not the resolved IP. An allowlisted
# name whose DNS points at a private or link-local address passes this check.
# Documented as out of scope — see docs/OWASP-MCP-COVERAGE.md, residual risk.
def _validate_fetch_url(url: str) -> None:
    """Reject a URL before it is ever requested. Applied to every redirect hop."""
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(f"scheme {parsed.scheme!r} not allowed; https only")

    # .hostname is already lowercased and strips any userinfo/port, so
    # "https://example.com@evil.tld" cannot masquerade as an allowed host.
    host = parsed.hostname
    if host is None or host.lower() not in ALLOWED_HOSTS:
        raise ValueError(f"host {host!r} is not on the allowlist")


def _fetch_doc(url: str) -> str:
    # Validate BEFORE issuing any request, then re-validate every hop. Handing
    # redirects to httpx via follow_redirects=True would let a hop reach an
    # unvalidated host, so hops are walked manually here.
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        _validate_fetch_url(current)

        response = httpx.get(
            current,
            follow_redirects=False,
            timeout=FETCH_TIMEOUT_SECONDS,
        )

        if not response.is_redirect:
            return response.text[:MAX_BODY_BYTES]

        location = response.headers.get("location")
        if not location:
            raise ValueError("redirect response is missing a location header")
        # Resolve relative redirect targets against the URL just requested.
        current = urljoin(current, location)

    raise ValueError(f"exceeded {MAX_REDIRECTS} redirect limit")


@mcp.tool(annotations=LOCAL_READONLY)
@audit
def ping(message: str) -> str:
    """Echo a message back. Smoke test only."""
    return f"pong: {message}"


@mcp.tool(annotations=LOCAL_READONLY)
@audit
def search_files(query: str) -> str:
    """Read a note from the sandbox directory."""
    return _read_sandboxed(query)


@mcp.tool(annotations=LOCAL_READONLY)
@audit
def query_records(filter: str) -> str:
    """Look up records by category."""
    return _query_records(filter)


@mcp.tool(annotations=OPEN_READONLY)
@audit
def fetch_doc(url: str) -> str:
    """Fetch the text of a document at a URL."""
    return _fetch_doc(url)


if __name__ == "__main__":
    mcp.run()
