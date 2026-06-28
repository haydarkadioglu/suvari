#!/usr/bin/env python3
"""Suvari MCP Server — multi-transport (streamable-http + SSE + health).
Run: python suvari_mcp.py              # 0.0.0.0:8000
     python suvari_mcp.py --port 8080
"""

from suvari.mcp_server import run_server

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
