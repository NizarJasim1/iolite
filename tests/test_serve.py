"""Control center — the engine-backed HUD payload and a live health check."""
import json
import os
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from iolite import serve


def test_demo_payload_is_engine_computed():
    p = serve.demo_payload()
    assert "spec" in p
    spec = p["spec"]
    assert spec["contract"] and spec["principals"]
    assert "probe_families" in spec["_iolite"]
    assert spec["_iolite"]["leads"]           # real leads from the engine


def test_dashboard_present_and_wired():
    assert os.path.exists(serve._DASH)
    html = open(serve._DASH, encoding="utf-8").read()
    for token in ("IOLITE", "/api/demo", "/api/health", "SURVEY",
                  "TRIAGE LEDGER", "ACQUISITION LOG"):
        assert token in html, token


def test_onyx_available_is_bool():
    assert isinstance(serve._onyx_available(), bool)


def test_research_payload_ranks_offline():
    p = serve.research_payload()          # bundled sample, no network
    progs = p["programs"]
    assert progs and progs[0]["tier"] in ("FOCUS", "ROTATE", "WATCH")
    assert progs[0]["score"] >= progs[-1]["score"]           # ranked
    assert "reasons" in progs[0] and progs[0]["reasons"]
    assert all(x["paid"] for x in progs)                     # VDP excluded


def test_live_health_and_demo_endpoints():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), serve._Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=5) as r:
            h = json.load(r)
        assert h["ok"] is True and "version" in h and isinstance(h["onyx_available"], bool)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/demo", timeout=15) as r:
            d = json.load(r)
        assert "spec" in d and d["spec"]["contract"]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            assert b"IOLITE" in r.read()
        # ONYX bridge endpoints
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/onyx", timeout=5) as r:
            o = json.load(r)
        assert "available" in o
        # research endpoint ranks the bundled sample over HTTP (offline)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/research?top=3", timeout=5) as r:
            rp = json.load(r)
        assert rp["programs"] and rp["programs"][0]["tier"]
        spec = d["spec"]
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/verify",
            data=json.dumps({"spec": spec}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            v = json.load(r)
        assert "available" in v            # real verify path exercised
        # live scan endpoint refuses a redacted spec (safety) — returns JSON, no crash
        req2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/onyx/scan",
            data=json.dumps({"spec": spec}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req2, timeout=15) as r:
            s = json.load(r)
        assert "ok" in s and s["ok"] is False    # redacted tokens / gated
    finally:
        srv.shutdown()


def test_dashboard_has_two_tab_shell():
    html = open(serve._DASH, encoding="utf-8").read()
    for token in ('data-tab="iolite"', 'data-tab="onyx"', 'id="onyxFrame"',
                  "ensureOnyx", "/api/onyx/launch"):
        assert token in html, token
