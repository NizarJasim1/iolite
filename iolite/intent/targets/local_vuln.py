"""
vuln_app.py (v2) — local authorized target with FOUR object kinds that exercise
every Wall-1 detection path. Pure stdlib. Listens on 127.0.0.1:8899.
  /notes/<id>  : BOLA, returns full object to anyone          -> value-presence FIRES
  /cards/<id>  : secure (owner check -> 403)                  -> CLEAN
  /badges/<id> : returns only SHARED-DEFAULT fields to anyone -> value-presence ABSTAINS (no FP)
  /flags/<id>  : returns a DERIVED bit of the owner's secret to anyone (no verbatim value)
                 -> value-presence abstains, METAMORPHIC oracle FIRES
PUT /<kind>/<id> : owner-only update (used by the metamorphic oracle to perturb OWN object).
"""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {"tokA": "userA", "tokB": "userB"}
STORE: dict[str, dict] = {"notes": {}, "cards": {}, "badges": {}, "flags": {}}
COUNTER = {"n": 0}

def _user(h):
    a = h.headers.get("Authorization", "")
    return USERS.get(a[7:]) if a.startswith("Bearer ") else None

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        ln = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(ln) or b"{}")

    def do_POST(self):
        user = _user(self)
        if not user: return self._send(401, {"error": "unauth"})
        kind = self.path.strip("/").split("/")[0]
        if kind not in STORE: return self._send(404, {"error": "no collection"})
        d = self._body(); COUNTER["n"] += 1; oid = str(COUNTER["n"])
        STORE[kind][oid] = {"id": oid, "owner": user,
                            "content": d.get("content", ""), "secret": d.get("secret", "")}
        return self._send(201, {"id": oid, "owner": user})

    def do_PUT(self):
        user = _user(self)
        if not user: return self._send(401, {"error": "unauth"})
        p = self.path.strip("/").split("/")
        if len(p) != 2 or p[0] not in STORE: return self._send(404, {"error": "nf"})
        obj = STORE[p[0]].get(p[1])
        if not obj: return self._send(404, {"error": "nf"})
        if obj["owner"] != user: return self._send(403, {"error": "forbidden"})  # owner-only update
        d = self._body()
        for k in ("content", "secret"):
            if k in d: obj[k] = d[k]
        return self._send(200, {"id": obj["id"], "updated": True})

    def do_GET(self):
        user = _user(self)
        if not user: return self._send(401, {"error": "unauth"})
        p = self.path.strip("/").split("/")
        if len(p) != 2 or p[0] not in STORE: return self._send(404, {"error": "nf"})
        kind, oid = p; obj = STORE[kind].get(oid)
        if not obj: return self._send(404, {"error": "nf"})
        if kind == "notes":                                   # BOLA: full object to anyone
            return self._send(200, obj)
        if kind == "cards":                                   # secure
            if obj["owner"] != user: return self._send(403, {"error": "forbidden"})
            return self._send(200, obj)
        if kind == "badges":                                  # shared-default only
            return self._send(200, {"id": oid, "type": "gold", "active": True})
        if kind == "flags":                                   # derived 1-bit of owner secret
            return self._send(200, {"id": oid, "has_long_secret": len(obj["secret"]) > 8})
        return self._send(404, {"error": "nf"})

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8899), H).serve_forever()
