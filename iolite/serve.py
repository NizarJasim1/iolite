"""
The IOLITE control center — a local, stdlib-only HUD that drives the REAL engine
and links IOLITE to ONYX.

  python -m iolite serve        # → http://127.0.0.1:8799  then press "Run demo scan"

Routes (pure http.server, no dependencies):
  GET /                → the purple dashboard (dashboard/index.html)
  GET /api/health      → {ok, version, onyx_available}
  GET /api/demo        → runs the demo pipeline on the fixtures, returns the ONYX
                         spec + dossier (everything shown is computed by the engine)
  GET /api/research    → ranks bug-bounty programs by fit for the toolchain
                         (?source=PATH&top=N; offline sample by default) — public data

Everything the dashboard renders comes from a real pipeline run — nothing is mocked.
The page can also load any IOLITE-emitted spec.json client-side (offline).
"""

from __future__ import annotations

import json
import os
import webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from . import onyx_link
from .pipeline import Inputs, run
from .roe import Engagement

_ONYX = {"proc": None, "url": None}      # a launched ONYX control center, if any

_PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DASH = os.path.join(_PKG, "dashboard", "index.html")
_FIX = os.path.join(_PKG, "fixtures")


def _onyx_available() -> bool:
    # delegate to the bridge, which first LOCATES ONYX (env ONYX_PATH → sys.path)
    # before importing — so the HUD pill agrees with the ONYX tab.
    return onyx_link.available()


def research_payload(source: str | None = None, top: int = 5) -> dict:
    """Rank programs for the HUD's Research panel. Offline by default (bundled
    sample) so the panel always shows something without network; pass a real
    dump path (source=) to rank live scope. PUBLIC data only — never a scan."""
    from . import research
    src = source or os.path.join(_FIX, "research_sample.json")
    try:
        progs = research.load_file(src)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "source": src, "programs": []}
    ranked = research.rank(progs, top=top)
    out = []
    for p in ranked:
        out.append({
            "score": p.score, "tier": p.tier, "name": p.name, "platform": p.platform,
            "handle": p.handle, "url": p.url, "paid": p.paid, "fresh": p.fresh,
            "buckets": sorted({a.bucket for a in p.assets if a.bucket != "other"}),
            "assets": len(p.assets),
            "resp_eff": p.resp_eff,
            "bounty_days": (round(p.bounty_hours / 24) if p.bounty_hours is not None else None),
            "reasons": [r.split(" ", 1)[1] for r in p.reasons[:4]],
            "payout_note": research.PAYOUT_NOTES.get(p.platform, "verify"),
        })
    return {"source": os.path.basename(src), "programs": out}


def demo_payload() -> dict:
    """Run the demo pipeline on the bundled fixtures and return spec + dossier.
    Factored out so it is unit-testable without starting a server."""
    eng = Engagement(
        program="IOLITE self-demo (fixtures)",
        authorized_by="in-repo fixtures (self-authored, always authorised)",
        operator="demo", in_scope_hosts=["shop.demo.test"],
        automation_permitted=True, allow_destructive=False, dry_run=True,
        own_accounts_only=True, attestation="Fixtures are self-authored and safe to test.")
    inp = Inputs(
        har_files=[os.path.join(_FIX, "capture_A.har"), os.path.join(_FIX, "capture_B.har")],
        js_files=[os.path.join(_FIX, "app.current.js")],
        sourcemap_files=[os.path.join(_FIX, "app.js.map")],
        archived_js_files=[os.path.join(_FIX, "app.archived.js")],
        graphql_file=os.path.join(_FIX, "graphql_introspection.json"))
    res = run(eng, inp, redact=True)
    return {"spec": res.spec, "dossier": res.dossier, "notes": res.model.notes}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):            # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                with open(_DASH, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(500, b"dashboard/index.html missing", "text/plain")
        elif path == "/api/health":
            from . import __version__
            self._send(200, json.dumps({"ok": True, "version": __version__,
                                        "onyx_available": _onyx_available()}))
        elif path == "/api/demo":
            try:
                self._send(200, json.dumps(demo_payload()))
            except Exception as e:      # never 500 silently — surface to the HUD
                self._send(200, json.dumps({"error": f"{type(e).__name__}: {e}"}))
        elif path == "/api/research":
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query)
            src = q.get("source", [None])[0]
            try:
                top = int(q.get("top", ["5"])[0])
            except ValueError:
                top = 5
            try:
                self._send(200, json.dumps(research_payload(src, top)))
            except Exception as e:
                self._send(200, json.dumps({"error": f"{type(e).__name__}: {e}", "programs": []}))
        elif path == "/api/onyx":
            self._send(200, json.dumps({"available": onyx_link.available(),
                                        "hud_url": _ONYX["url"]}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except Exception:
            body = {}
        if path == "/api/verify":
            # run the CURRENT spec (from the HUD) through ONYX's own loaders — the
            # real, operational agreement check between the two tools.
            self._send(200, json.dumps(onyx_link.verify_spec(body.get("spec") or {})))
        elif path == "/api/onyx/launch":
            # Idempotent + readiness-accurate: the HUD polls this until ready=true,
            # and only then points the iframe at ONYX (so it never frames a blank).
            if _ONYX["url"] is None:
                proc, res = onyx_link.launch_server()
                if proc is not None:
                    _ONYX["proc"] = None if proc == "existing" else proc
                    _ONYX["url"] = res
                    ready = onyx_link.wait_until_up(res, timeout=10)
                    self._send(200, json.dumps({"ok": True, "url": res, "ready": ready}))
                else:
                    self._send(200, json.dumps({"ok": False, "error": res}))
            else:
                ready = onyx_link.wait_until_up(_ONYX["url"], timeout=10)
                self._send(200, json.dumps({"ok": True, "url": _ONYX["url"], "ready": ready}))
        elif path == "/api/onyx/scan":
            # run a LIVE ONYX scan from the current spec (refuses redacted tokens)
            import tempfile
            spec = body.get("spec") or {}
            try:
                fd, p = tempfile.mkstemp(suffix=".json")
                with os.fdopen(fd, "w") as fh:
                    json.dump(spec, fh)
                self._send(200, json.dumps(onyx_link.scan(p)))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
        else:
            self._send(404, json.dumps({"error": "not found"}))


def serve(host: str = "127.0.0.1", port: int = 8799, open_browser: bool = True) -> None:
    srv = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"
    onyx = "detected" if _onyx_available() else "not on PYTHONPATH"
    print(f"IOLITE control center → {url}   (ONYX: {onyx})")
    print("press Ctrl-C to stop")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
        srv.shutdown()
