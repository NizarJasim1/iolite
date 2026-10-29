"""
wall3_benchmark_app.py — a FAIR, LABELED write-side authz benchmark (local HTTP).
Composition mirrors the REAL distribution (arXiv:2605.25865, n=84): action-level
writes dominate, delete ~15.5%, object-rebinding present, plus workflow-context.
Fairness (so it is NOT a circular self-test): it contains
  - VULN ops the engine SHOULD find (write/role/owner/soft-delete BOLA),
  - VULN ops the engine SHOULD REFUSE for safety (hard-delete, external notify),
  - a VULN the engine SHOULD MISS by design (state-gated workflow write),
  - SECURE controls and DECOYS it must NOT flag (noop, shared-default).
Ground truth is served at GET /labels. Static bearer auth: tokA->A, tokB->B.
"""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {"tokA": "A", "tokB": "B"}
DB: dict = {}; N = {"i": 0}; EXTERNAL: list = []

LABELS = {
    "update_field":     {"taxonomy": "write-BOLA (action-level)", "truth": "VULN_FINDABLE"},
    "set_role":         {"taxonomy": "BOPLA-write (mass-assignment)", "truth": "VULN_FINDABLE"},
    "change_owner":     {"taxonomy": "object-rebinding", "truth": "VULN_FINDABLE"},
    "soft_delete":      {"taxonomy": "delete-BOLA (reversible)", "truth": "VULN_FINDABLE"},
    "hard_delete":      {"taxonomy": "delete-BOLA (irreversible)", "truth": "VULN_REFUSE_SAFETY"},
    "advance_workflow": {"taxonomy": "workflow-context write (state-gated)", "truth": "VULN_MISS_BYDESIGN"},
    "notify":           {"taxonomy": "external-effect trigger", "truth": "VULN_REFUSE_SAFETY"},
    "update_secure":    {"taxonomy": "secure update (owner-only)", "truth": "SECURE"},
    "update_noop":      {"taxonomy": "decoy: 200 but no persist", "truth": "DECOY"},
    "update_shared":    {"taxonomy": "decoy: shared-default value", "truth": "DECOY"},
}

def _u(h):
    a = h.headers.get("Authorization", "")
    return USERS.get(a[7:]) if a.startswith("Bearer ") else None

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Length", str(len(b))); self.send_header("Content-Type","application/json")
        self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}

    def do_GET(self):
        if self.path == "/labels": return self._s(200, LABELS)
        if self.path == "/_external": return self._s(200, {"count": len(EXTERNAL)})
        u = _u(self)
        if not u: return self._s(401, {"e": "unauth"})
        p = self.path.strip("/").split("/")
        if len(p) == 2 and p[0] == "obj":
            o = DB.get(p[1])
            return self._s(200, o) if o else self._s(404, {"e": "gone"})
        return self._s(404, {"e": "nf"})

    def do_POST(self):
        u = _u(self)
        if not u: return self._s(401, {"e": "unauth"})
        p = self.path.strip("/").split("/"); self._body()
        if self.path == "/obj":
            N["i"] += 1; oid = f"{N['i']}"
            DB[oid] = {"id": oid, "owner": u, "content": "init", "role": "user", "state": "draft"}
            return self._s(201, DB[oid])
        if len(p) == 3 and p[0] == "obj":
            oid, act = p[1], p[2]
            if act == "undelete":
                # recover from trash (soft-deleted)
                t = DB.get("_trash_" + oid)
                if t: DB[oid] = t; DB.pop("_trash_" + oid); return self._s(200, {"ok": True})
                return self._s(404, {"e": "nf"})
            if oid not in DB: return self._s(404, {"e": "gone"})
            if act == "advance":                      # state-gated: only from 'ready' (BOLA-but-miss)
                if DB[oid]["state"] != "ready": return self._s(409, {"e": "wrong state"})
                DB[oid]["state"] = "done"; return self._s(200, DB[oid])
            if act == "notify":                        # external effect (no owner check)
                EXTERNAL.append((u, oid)); return self._s(200, {"sent": True})
        return self._s(404, {"e": "nf"})

    def do_PUT(self):
        u = _u(self)
        if not u: return self._s(401, {"e": "unauth"})
        p = self.path.strip("/").split("/"); b = self._body()
        if len(p) == 3 and p[0] == "obj":
            oid, act = p[1], p[2]
            if oid not in DB: return self._s(404, {"e": "gone"})
            o = DB[oid]
            if act == "field":     o["content"] = b.get("value", ""); return self._s(200, o)   # write-BOLA
            if act == "role":      o["role"] = b.get("value", ""); return self._s(200, o)       # BOPLA
            if act == "owner":     o["owner"] = b.get("value", ""); return self._s(200, o)      # rebind
            if act == "secure":                                                                  # owner-only
                if o["owner"] != u: return self._s(403, {"e": "forbidden"})
                o["content"] = b.get("value", ""); return self._s(200, o)
            if act == "noop":      return self._s(200, o)                                         # decoy: no persist
            if act == "shared":    o["content"] = "PUBLIC"; return self._s(200, o)               # decoy: shared default
        return self._s(404, {"e": "nf"})

    def do_DELETE(self):
        u = _u(self)
        if not u: return self._s(401, {"e": "unauth"})
        p = self.path.strip("/").split("/")
        if len(p) == 3 and p[0] == "obj":
            oid, act = p[1], p[2]
            if oid not in DB: return self._s(404, {"e": "gone"})
            if act == "soft":  DB["_trash_" + oid] = DB.pop(oid); return self._s(200, {"ok": True})  # reversible
            if act == "hard":  DB.pop(oid, None); return self._s(200, {"ok": True})                 # irreversible
        return self._s(404, {"e": "nf"})

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8911), H).serve_forever()
