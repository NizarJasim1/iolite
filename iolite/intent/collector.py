"""
collector.py — the local, loopback-only receiver behind `iolite watch`.

A tiny stdlib HTTP server (127.0.0.1) that: serves the live in-page hook, receives the
request/response pairs your own browser emits (one POST per call), feeds them to a
`LiveSession`, and streams confirmations/leads back. It crafts no traffic of its own and
binds only to localhost. In-scope hosts are enforced inside the session.

Endpoints:
  GET  /                -> status (JSON)
  GET  /live-hook.js    -> the instrumentation hook (origin injected)
  POST /ingest          -> {principal, method, url, reqBody, status, respBody} -> events
  GET  /status          -> session status
  GET  /dossier         -> current Markdown dossier
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .live_session import LiveSession

_HOOK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "assets", "iolite_live_hook.js")


_DASH_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "assets", "iolite_dashboard.html")


def _load_hook() -> str:
    try:
        with open(_HOOK_PATH, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return "/* iolite live hook asset missing */"


def _load_dashboard() -> str:
    try:
        with open(_DASH_PATH, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return "<!doctype html><title>IOLITE</title><p>dashboard asset missing</p>"


class Collector:
    def __init__(self, session: LiveSession, host: str = "127.0.0.1", port: int = 8777,
                 on_event=None):
        self.session = session
        self.host, self.port = host, port
        self.on_event = on_event or (lambda ev: None)
        self._httpd = None
        self._thread = None
        self._snap = (0.0, None)         # (timestamp, cached snapshot dict)

    def _snapshot_cached(self, ttl: float = 3.0) -> dict:
        import time as _t
        now = _t.monotonic()
        if self._snap[1] is not None and now - self._snap[0] < ttl:
            return self._snap[1]
        rep = self.session.snapshot()
        data = {"policy": getattr(rep, "learned_policy", {}) or self.session.policy(),
                "leads": [{"family": c.family, "method": c.method, "path": c.path,
                           "attacker": c.attacker, "payout": c.payout, "severity": c.severity,
                           "derivation": c.derivation} for c in rep.leads[:40]],
                "by_family": rep.by_family,
                "corroborated": len(rep.corroborated)}
        self._snap = (now, data)
        return data

    def _handler(self):
        session, on_event, coll = self.session, self.on_event, self
        origin = f"http://{self.host}:{self.port}"

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):           # quiet
                return

            def _cors(self):
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "content-type")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

            def _json(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self._cors()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(204); self._cors(); self.end_headers()

            def _raw(self, body, ctype):
                b = body.encode() if isinstance(body, str) else body
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self._cors()
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _qs(self, key, default=""):
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(self.path).query)
                return (q.get(key, [default]) or [default])[0]

            def do_GET(self):
                p = self.path.split("?", 1)[0]
                if p in ("/", "/dashboard"):
                    html = _load_dashboard().replace("__IOLITE_COLLECTOR__", origin)
                    self._raw(html, "text/html; charset=utf-8")
                elif p == "/live-hook.js":
                    self._raw(_load_hook().replace("__IOLITE_COLLECTOR__", origin),
                              "application/javascript")
                elif p == "/events":
                    try:
                        since = int(self._qs("since", "0") or 0)
                    except ValueError:
                        since = 0
                    self._json({"events": session.events_since(since), "next": session._evseq})
                elif p == "/policy":
                    self._json(session.policy())
                elif p == "/graph":
                    self._json(session.graph())
                elif p == "/snapshot":
                    self._json(coll._snapshot_cached())
                elif p == "/dossier":
                    from . import dossier
                    self._raw(dossier.render(session.snapshot()), "text/markdown; charset=utf-8")
                else:
                    self._json(session.status())

            def do_POST(self):
                if not self.path.startswith("/ingest"):
                    return self._json({"error": "not found"}, 404)
                try:
                    n = int(self.headers.get("Content-Length", 0) or 0)
                    raw = self.rfile.read(n) if n else b"{}"
                    rec = json.loads(raw.decode("utf-8", "replace") or "{}")
                except Exception:
                    return self._json({"error": "bad json"}, 400)
                _st = rec.get("status")
                events = session.ingest_raw(
                    principal=str(rec.get("principal") or "P"),
                    method=str(rec.get("method") or "GET"),
                    url=str(rec.get("url") or ""),
                    req_body=_maybe_json(rec.get("reqBody")),
                    status=(int(_st) if _st is not None else 200),  # response received; assume ALLOW if unstated
                    resp_body=_maybe_json(rec.get("respBody")),
                    req_headers=rec.get("reqHeaders") if isinstance(rec.get("reqHeaders"), dict) else None,
                    resp_headers=rec.get("respHeaders") if isinstance(rec.get("respHeaders"), dict) else None,
                    claims=rec.get("claims") if isinstance(rec.get("claims"), dict) else None)
                for ev in events:
                    if ev.kind != "dropped":
                        on_event(ev)
                return self._json({"events": [{"kind": e.kind, "severity": e.severity,
                                               "title": e.title} for e in events]})
        return H

    def start(self):
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._handler())
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()

    def snippet(self, principal: str = "A") -> str:
        """The one-liner to paste in each account's DevTools console (or a bookmarklet)."""
        origin = f"http://{self.host}:{self.port}"
        return (f'window.__IOLITE_principal="{principal}";'
                f'window.__IOLITE_collector="{origin}";'
                f's=document.createElement("script");s.src="{origin}/live-hook.js";'
                f'document.head.appendChild(s);')


def _maybe_json(v):
    if isinstance(v, (dict, list)):
        return v
    if isinstance(v, str) and v:
        try:
            return json.loads(v)
        except Exception:
            return {}
    return {}
