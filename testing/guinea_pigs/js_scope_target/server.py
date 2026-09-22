"""JS scope lab: one stdlib HTTP server, two roles.

ROLE=target   the project's only target (192.88.97.10). Serves a page whose
              bundle names in-scope endpoints, an in-scope port nmap/naabu is
              never asked to scan, and a set of third-party URLs.
ROLE=outsider a reachable host that is NOT a project target (192.88.97.20).
              The bundle names it; nothing in the scan may write it to the
              graph or send it a request. Every request is logged to prove it.
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "target")
PORTS = [int(p) for p in os.environ.get("PORTS", "80").split(",")]
HERE = os.path.dirname(os.path.abspath(__file__))

INDEX = b"""<!doctype html>
<html><head><title>JS scope lab</title></head>
<body>
<h1>JS scope lab</h1>
<p><a href="/about">About</a></p>
<script src="/static/app.js"></script>
</body></html>
"""

ABOUT = b"""<!doctype html>
<html><head><title>About</title></head>
<body><p>Nothing to see.</p><script src="/static/app.js"></script></body></html>
"""


def _static(name: str) -> bytes:
    with open(os.path.join(HERE, "static", name), "rb") as f:
        return f.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "jsscope/1.0"

    def log_message(self, fmt, *args):
        sys.stdout.write(f"[{ROLE}:{self.server.server_port}] {self.client_address[0]} "
                         f"{self.command} {self.path}\n")
        sys.stdout.flush()

    def _send(self, status, body, ctype="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if ROLE == "outsider":
            return self._send(200, b'{"partner": true}', "application/json")
        if path in ("/", "/index.html"):
            return self._send(200, INDEX)
        if path == "/about":
            return self._send(200, ABOUT)
        if path in ("/static/app.js", "/static/partial.js"):
            return self._send(200, _static(path.rsplit("/", 1)[1]), "application/javascript")
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\n", "text/plain")
        if path.startswith("/api/") or path in ("/graphql", "/socket"):
            return self._send(200, b'{"ok": true}', "application/json")
        return self._send(404, b"not found", "text/plain")

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_POST(self):
        self._send(200, b'{"ok": true}', "application/json")


def main():
    servers = [ThreadingHTTPServer(("0.0.0.0", port), Handler) for port in PORTS]
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[{ROLE}] listening on {PORTS}", flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
