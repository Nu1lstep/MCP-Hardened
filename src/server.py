from fastmcp import FastMCP

mcp = FastMCP("hardened-demo")

@mcp.tool
def ping(message: str) -> str:
    """Echo a message back. Smoke test only."""
    return f"pong: {message}"

if __name__ == "__main__":
    mcp.run()
