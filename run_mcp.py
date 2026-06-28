#!/usr/bin/env python3
"""
Suvari MCP Server Launcher — binds to 0.0.0.0 for external access.
Usage:
  python run_mcp.py              # streamable-http on 0.0.0.0:8000
  python run_mcp.py --sse        # SSE transport
  python run_mcp.py --port 8080  # Custom port
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from suvari.mcp_server import mcp

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sse", action="store_true", help="SSE transport")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    transport = "sse" if args.sse else "streamable-http"
    print(f"Suvari MCP listening on {args.host}:{args.port} ({transport})")

    # Set host/port before run()
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.run(transport=transport)
