import sqlite3
from pathlib import Path

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


if __name__ == "__main__":
    mcp.run()
