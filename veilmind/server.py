"""Loopback-only web UI. Binds to 127.0.0.1 so nothing is reachable from the network."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import llm, pipeline
from .vault import Vault, VaultError

STATIC = Path(__file__).parent / "static"
VAULT: Vault


def load_env() -> None:
    for p in (Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"):
        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def full_state() -> dict:
    s = VAULT.state()
    s["model"] = llm.MODEL
    s["live"] = llm.have_key()
    return s


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the terminal clean
        pass

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            data = (STATIC / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/api/state":
            self._json(full_state())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._json({"error": "bad json"}, 400)
        try:
            if self.path == "/api/ask":
                text = str(body.get("text", ""))[:4000]
                if not text.strip():
                    return self._json({"ok": False, "error": "Type a message first."})
                self._json({**pipeline.ask(VAULT, text), "state": full_state()})
            elif self.path == "/api/toggle":
                VAULT.toggle(int(body.get("index", -1)))
                self._json(full_state())
            elif self.path == "/api/rotate":
                VAULT.rotate()
                self._json(full_state())
            else:
                self._json({"error": "not found"}, 404)
        except VaultError as e:
            self._json({"ok": False, "error": str(e)}, 400)


def main() -> None:
    global VAULT
    load_env()
    VAULT = Vault()
    port = int(os.environ.get("PORT", "8765"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    mode = f"LIVE · Gemini ({llm.MODEL})" if llm.have_key() else "MOCK (set GEMINI_API_KEY in .env for live mode)"
    print(f"Veilmind  http://127.0.0.1:{port}   mode: {mode}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
