"""
Deliberately vulnerable localhost HTTP server for exercising the autonomous
loop in tests. Binds loopback only, serves canned responses, no real network.

Vulnerabilities exposed:
  * GET /.git/config      -> 200, contains "[core]"            (git exposure)
  * GET /admin            -> 200, weak login form              (exposed admin)
  * missing CSP / X-Frame-Options on every response           (missing headers)
  * GET /backup/          -> 200, directory listing            (dir listing)
  * GET /robots.txt       -> 200, discloses /internal/         (info leak)
  * GET /internal/        -> 200, internal area                (disclosed path)

Run standalone:  python tests/fixtures/vuln_server.py [port]
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROUTES = {
    "/": (200, "text/html",
          "<html><body><h1>Acme Corp</h1><p>Welcome.</p></body></html>"),
    "/.git/config": (200, "text/plain",
                     "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                     '[remote "origin"]\n\turl = git@github.com:acme/secret.git\n'),
    "/admin": (200, "text/html",
               "<html><body><h1>Admin Login</h1>"
               "<form method=post action=/admin>"
               "<input name=username>"
               "<input name=password type=password>"
               "<button>Log in</button></form></body></html>"),
    "/backup/": (200, "text/html",
                 "<html><head><title>Directory listing for /backup/</title></head>"
                 "<body><h2>Directory listing for /backup/</h2><ul>"
                 "<li><a href='db.sql'>db.sql</a></li>"
                 "<li><a href='site.tar.gz'>site.tar.gz</a></li></ul></body></html>"),
    "/robots.txt": (200, "text/plain",
                    "User-agent: *\nDisallow: /internal/\nDisallow: /admin\n"),
    "/internal/": (200, "text/html",
                   "<html><body><h1>Internal area</h1>"
                   "<p>staff only dashboards</p></body></html>"),
}


class VulnHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # silence test noise
        pass

    def do_GET(self):  # noqa: N802
        self.server.hits.append(self.path)
        route = _ROUTES.get(self.path)
        if route is None:
            body = b"<html><body><h1>404 Not Found</h1></body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        status, ctype, text = route
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # NOTE: intentionally no Content-Security-Policy / X-Frame-Options.
        self.end_headers()
        self.wfile.write(body)


def serve(port: int = 0) -> tuple[ThreadingHTTPServer, str, threading.Thread]:
    """Start the server on loopback. Returns (server, base_url, thread).

    Every request path received is appended to ``server.hits``.
    """
    httpd = ThreadingHTTPServer(("127.0.0.1", port), VulnHandler)
    httpd.hits = []
    host, bound = httpd.server_address[0], httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, f"http://{host}:{bound}", thread


if __name__ == "__main__":
    import sys
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    srv, url, _ = serve(p)
    print(f"vuln server on {url}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
