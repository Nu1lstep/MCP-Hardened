from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("hardened-demo")

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / "sandbox"


def _read_sandboxed(query: str) -> str:
    path = SANDBOX / query
    return path.read_text()


@mcp.tool
def ping(message: str) -> str:
    """Echo a message back. Smoke test only."""
    return f"pong: {message}"


@mcp.tool
def search_files(query: str) -> str:
    """Read a note from the sandbox directory."""
    return _read_sandboxed(query)

if __name__ == "__main__":
    mcp.run()
