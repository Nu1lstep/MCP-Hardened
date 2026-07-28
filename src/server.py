import sqlite3
from pathlib import Path

import httpx
from fastmcp import FastMCP

mcp = FastMCP("hardened-demo")

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / "sandbox"
DB_PATH = ROOT / "data" / "records.db"

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


def _read_sandboxed(query: str) -> str:
    path = SANDBOX / query
    return path.read_text()


def _query_records(filter: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    sql = f"SELECT id, name, category, note FROM records WHERE category = '{filter}'"
    rows = cursor.execute(sql).fetchall()
    conn.close()
    if not rows:
        return "No matching records."
    return "\n".join(
        f"[{row[0]}] {row[1]} ({row[2]}): {row[3]}" for row in rows
    )


def _fetch_doc(url: str) -> str:
    response = httpx.get(url, follow_redirects=True)
    return response.text


@mcp.tool(annotations=LOCAL_READONLY)
def ping(message: str) -> str:
    """Echo a message back. Smoke test only."""
    return f"pong: {message}"


@mcp.tool(annotations=LOCAL_READONLY)
def search_files(query: str) -> str:
    """Read a note from the sandbox directory."""
    return _read_sandboxed(query)


@mcp.tool(annotations=LOCAL_READONLY)
def query_records(filter: str) -> str:
    """Look up records by category."""
    return _query_records(filter)


@mcp.tool(annotations=OPEN_READONLY)
def fetch_doc(url: str) -> str:
    """Fetch the text of a document at a URL."""
    return _fetch_doc(url)


if __name__ == "__main__":
    mcp.run()
