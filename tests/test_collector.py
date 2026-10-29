"""
collector — the loopback receiver behind `iolite watch`. Real HTTP: start it, POST
request/response pairs as the in-page hook would, and assert it confirms live and serves
the hook. Binds only to 127.0.0.1.
"""
import json
import urllib.request

from iolite.intent.live_session import LiveSession
from iolite.intent.collector import Collector

_PORT = 8796


def _post(port, rec):
    r = urllib.request.urlopen(f"http://127.0.0.1:{port}/ingest",
                               data=json.dumps(rec).encode(), timeout=3)
    return json.loads(r.read())


def _get(port, path):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3).read().decode()


def test_collector_ingest_confirms_live():
    s = LiveSession(scope_hosts={"api.t.com"})
    c = Collector(s, port=_PORT).start()
    try:
        _post(_PORT, {"principal": "alice", "method": "POST", "url": "https://api.t.com/api/v/1",
                      "status": 201, "respBody": json.dumps({"id": "1", "secret": "tok_abc12345"})})
        _post(_PORT, {"principal": "alice", "method": "GET", "url": "https://api.t.com/api/v/1",
                      "status": 200, "respBody": json.dumps({"id": "1", "secret": "tok_abc12345"})})
        out = _post(_PORT, {"principal": "bob", "method": "GET", "url": "https://api.t.com/api/v/1",
                            "status": 200, "respBody": json.dumps({"id": "1", "secret": "tok_abc12345"})})
        assert any(e["kind"] == "corroborated" for e in out["events"])
        st = json.loads(_get(_PORT, "/status"))
        assert st["corroborated"] == 1 and set(st["principals"]) == {"alice", "bob"}
    finally:
        c.stop()


def test_collector_serves_hook_with_origin():
    s = LiveSession(scope_hosts={"api.t.com"})
    c = Collector(s, port=_PORT + 1).start()
    try:
        js = _get(_PORT + 1, "/live-hook.js")
        assert f"127.0.0.1:{_PORT + 1}" in js        # origin injected
        assert "IOLITE live hook" in js and "armed" in js
    finally:
        c.stop()


def test_collector_drops_out_of_scope():
    s = LiveSession(scope_hosts={"api.t.com"})
    c = Collector(s, port=_PORT + 2).start()
    try:
        _post(_PORT + 2, {"principal": "bob", "method": "GET", "url": "https://evil.com/x/9",
                          "status": 200, "respBody": json.dumps({"secret": "tok_out12345"})})
        st = json.loads(_get(_PORT + 2, "/status"))
        assert st["exchanges"] == 0
    finally:
        c.stop()
