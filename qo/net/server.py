"""Stdlib HTTP server: serves the PWA dashboard + JSON telemetry API."""
from __future__ import annotations

import json
import os
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "web")


class Handler(SimpleHTTPRequestHandler):
    orchestrator = None  # set by serve()

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=os.path.abspath(WEB_DIR), **kw)

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        orch = Handler.orchestrator or {}
        if self.path == "/api/health":
            return self._json({"status": "ok", "version": "0.1.0-quantum"})
        if self.path == "/api/telemetry":
            tele = orch.get("telemetry")
            return self._json(tele.snapshot() if tele else {})
        if self.path == "/api/swarm":
            swarm = orch.get("swarm")
            return self._json(swarm.health() if swarm else {})
        if self.path == "/api/remediation":
            rem = orch.get("remediation")
            return self._json(rem.report() if rem else {})
        return super().do_GET()

    def log_message(self, *a):
        pass  # quiet


def serve_blocking(host: str, port: int, orchestrator: dict):
    Handler.orchestrator = orchestrator
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"QO-75 dashboard → http://{host}:{port}  (PWA installable)")
    srv.serve_forever()


def serve_in_thread(host: str, port: int, orchestrator: dict) -> threading.Thread:
    t = threading.Thread(target=serve_blocking, args=(host, port, orchestrator),
                         daemon=True)
    t.start()
    return t
