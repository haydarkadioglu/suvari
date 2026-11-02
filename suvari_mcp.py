#!/usr/bin/env python3
"""Suvari MCP Server — multi-transport (streamable-http + SSE + health).
Run: python suvari_mcp.py              # 127.0.0.1:8000
     python suvari_mcp.py --port 8080
"""

if __name__ == "__main__":
    import argparse

    from suvari.mcp_server import configure_logging

    configure_logging()

    # Import run_server only after logging is configured, so tool registration
    # (which emits the "MCP ready" line) is observable on the console.
    from suvari.mcp_server import default_host, default_port, resolve_token, run_server

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=default_host(), help="Bind address (default: loopback)")
    parser.add_argument("--port", type=int, default=default_port())
    parser.add_argument(
        "--token",
        default=resolve_token(),
        help="Bearer token required from clients (default: $SUVARI_MCP_TOKEN; empty disables auth)",
    )
    args = parser.parse_args()
    try:
        run_server(host=args.host, port=args.port, token=args.token)
    except ValueError as exc:
        # A refused bind must not look like a crash: print the reason and exit 1
        raise SystemExit(f"error: {exc}") from None
