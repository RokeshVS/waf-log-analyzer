#!/usr/bin/env python
"""
Entrypoint to start the WAF MCP server with configurable transport.
"""

import asyncio
import logging
import os
import sys
from app.mcp_server import mcp

# Configure root logger to output to stdout for Docker capture
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger("waf-analyzer.entrypoint")


async def main():
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()

    if transport == "http":
        host = os.environ.get("MCP_HOST", "0.0.0.0")  # Matches your compose 0.0.0.0 bind
        port = int(os.environ.get("MCP_PORT", "5000"))
        
        logger.info(f"Starting MCP server in HTTP mode on {host}:{port}")
        
        # ✅ Use run_async() inside async contexts, not run()
        await mcp.run_async(
            transport="http",
            host=host,
            port=port,
        )
    else:
        logger.info("Starting MCP server in stdio mode")
        # ✅ Same fix for stdio
        await mcp.run_async(transport="stdio")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("MCP server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Server crashed with unhandled exception: {e}", exc_info=True)
        sys.exit(1)