#!/usr/bin/env python3
"""Suvari MCP Server — multi-transport (streamable-http + SSE + health).
Run: python suvari_mcp.py              # 0.0.0.0:8000
     python suvari_mcp.py --port 8080
"""

if __name__ == "__main__":
    import argparse

    from suvari.mcp_server import configure_logging

    configure_logging()

    # Import run_server only after logging is configured, so tool registration
    # (which emits the "MCP ready" line) is observable on the console.
    from suvari.mcp_server import run_server

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
