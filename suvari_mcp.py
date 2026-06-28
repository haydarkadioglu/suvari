#!/usr/bin/env python3
"""Suvari MCP Entry Point.
Run: python suvari_mcp.py          # localhost-only
     python suvari_mcp.py --host 0.0.0.0   # external access
"""

from suvari.mcp_server import mcp

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.run(transport="streamable-http")
