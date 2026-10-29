"""
The live dashboard endpoints served by the collector: /, /events, /policy, /graph, /snapshot.
Real loopback HTTP.
"""
import json
import urllib.request

from iolite.intent.live_session import LiveSession
from iolite.intent.collector import Collector

_PORT = 8824


def _get(port, path):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3).read().decode()


def _post(port, rec):
    urllib.request.urlopen(f"http://127.0.0.1:{port}/ingest",
                           data=json.dumps(rec).encode(), timeout=3).read()


def _drive(port):
    _post(port, {"principal": "alice", "method": "POST", "url": "https://api.t.com/api/vault",
                 "status": 201, "claims": {"sub": "u_alice"},
                 "respBody": json.dumps({"id": "1001", "owner_id": "u_alice", "secret": "tok_x1y2z3q"})})
    _post(port, {"principal": "alice", "method": "GET", "url": "https://api.t.com/api/vault/1001",
                 "claims": {"sub": "u_alice"},
                 "respBody": json.dumps({"id": "1001", "owner_id": "u_alice", "secret": "tok_x1y2z3q"})})
    _post(port, {"principal": "bob", "method": "GET", "url": "https://api.t.com/api/vault/1001",
                 "claims": {"sub": "u_bob"},
                 "respBody": json.dumps({"id": "1001", "owner_id": "u_alice", "secret": "tok_x1y2z3q"})})
    _post(port, {"principal": "carol", "method": "GET", "url": "https://api.t.com/api/vault/1001",
                 "status": 403, "claims": {"sub": "u_carol"}, "respBody": json.dumps({"error": "forbidden"})})


def test_dashboard_html_served():
    s = LiveSession(scope_hosts={"api.t.com"}); c = Collector(s, port=_PORT).start()
    try:
        html = _get(_PORT, "/")
        # original v1.22 visual identity, unchanged (exact mark + original card titles)
        assert "◈ IOLITE LIVE" in html
        assert "Principals &amp; ownership" in html and "EV-ranked leads" in html
        # same data contract still consumed by the same render code
        assert "/events" in html and "/policy" in html and "/graph" in html and "/snapshot" in html
        # interactivity + physics layered on the existing elements
        assert "countUp(" in html          # animated count-ups on the header pills
        assert "flingHome(" in html        # draggable principal chips spring back (physics)
        assert "ripple(" in html           # press ripple on pills/leads
        assert "SIM" in html               # alive-on-open demo stream
        # the rejected v1.23 redesign is gone
        assert "OPERATIONS TABLE" not in html and "gcanvas" not in html
    finally:
        c.stop()


def test_events_policy_graph_snapshot():
    s = LiveSession(scope_hosts={"api.t.com"}); c = Collector(s, port=_PORT + 1).start()
    try:
        _drive(_PORT + 1)
        ev = json.loads(_get(_PORT + 1, "/events?since=0"))
        kinds = {e["kind"] for e in ev["events"]}
        assert "corroborated" in kinds and "boundary_learned" in kinds
        pol = json.loads(_get(_PORT + 1, "/policy"))
        assert pol["object_types"]["vault"]["enforced"] is True
        g = json.loads(_get(_PORT + 1, "/graph"))
        assert {"alice", "bob", "carol"} <= {p["pid"] for p in g["principals"]}
        assert len(g["confirmations"]) == 1
        snap = json.loads(_get(_PORT + 1, "/snapshot"))
        assert "leads" in snap and "by_family" in snap
    finally:
        c.stop()


def test_events_incremental_cursor():
    s = LiveSession(scope_hosts={"api.t.com"}); c = Collector(s, port=_PORT + 2).start()
    try:
        _drive(_PORT + 2)
        first = json.loads(_get(_PORT + 2, "/events?since=0"))
        nxt = first["next"]
        more = json.loads(_get(_PORT + 2, f"/events?since={nxt}"))
        assert more["events"] == []        # nothing new since the cursor
    finally:
        c.stop()
