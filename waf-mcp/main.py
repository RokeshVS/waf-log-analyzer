"""Entry point for the AWS WAF MCP server.

Run modes:
  stdio (default) — for use with Claude Desktop and local MCP clients:
      python main.py

  http — exposes an SSE endpoint for remote MCP clients:
      python main.py --transport http --host 0.0.0.0 --port 5000
"""

from __future__ import annotations

import argparse
import sys

from app.mcp_server import mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS WAF Log Analysis MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport to use (default: stdio)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host for HTTP transport (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port for HTTP transport (default: 5000)")
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
