"""
authz_prober.py — the OPERATIONAL Wall-1 engine (real HTTP, real Delta-state).

It turns the interventional principle into a running tool:
  for each createable object KIND the operator declares:
    1. CREATE as A (intervention) with a UNIQUE private marker -> get id
    2. OWNER CONTROL: GET as A must reproduce the marker (proves the object is
       real, private, and readable by its owner); else SKIP (cannot establish)
    3. MANUFACTURED NEGATIVE (by construction): A created it privately, B was
       never granted -> "B must not read it" is ground-truth intent-deny
    4. PROBE as B: GET the same id as B
    5. CONFIRM by VALUE-PRESENCE (Delta-state), NEVER by status code alone:
         - B blocked (401/403/404)            -> CLEAN (enforced deny)
         - B's body reproduces A's marker     -> FINDING (leak PROVEN)
         - B 200 but marker ABSENT            -> ABSTAIN (no proof -> no claim; zero-FP)
Config-driven: the bug is NOT hard-coded; the same loop runs over every kind.
Pure stdlib. Legal-by-construction: only the operator's OWN principals/objects.
"""
from __future__ import annotations
import json, sys, urllib.request, urllib.error
from dataclasses import dataclass

BASE = "http://127.0.0.1:8899"
A_TOK, B_TOK = "tokA", "tokB"

# A marker only A's object carries. Value-presence of THIS in B's response is
# the sound Delta-state witness that B reproduced A's specific private content.
MARKER = "PRIVATE-A-7f3c9e21"

@dataclass
class Resp:
    status: int
    body: str

def http(method: str, path: str, token: str, payload: dict | None = None) -> Resp:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return Resp(r.status, r.read().decode())
    except urllib.error.HTTPError as e:
        return Resp(e.code, e.read().decode())
    except Exception as e:                      # noqa: BLE001
        return Resp(-1, str(e))

# Each kind = a producer (create) + a consumer (read-by-id) endpoint pair.
# In production IOLITE's surface model supplies these; here we declare them.
KINDS = [
    {"name": "notes", "create": "/notes", "read": "/notes/{id}"},
    {"name": "cards", "create": "/cards", "read": "/cards/{id}"},
]

def probe_kind(k: dict) -> dict:
    # 1. intervention: A creates a private object carrying the marker
    cr = http("POST", k["create"], A_TOK, {"content": MARKER})
    if cr.status not in (200, 201):
        return {"kind": k["name"], "verdict": "SKIP", "why": f"create failed ({cr.status})"}
    oid = json.loads(cr.body)["id"]
    read_path = k["read"].format(id=oid)

    # 2. owner control: A must reproduce the marker (object real & owner-readable)
    av = http("GET", read_path, A_TOK)
    if not (av.status == 200 and MARKER in av.body):
        return {"kind": k["name"], "verdict": "SKIP", "why": "owner control failed"}

    # 3. (manufactured negative established by construction: B never granted)
    # 4. probe as B
    bv = http("GET", read_path, B_TOK)

    # 5. confirm by value-presence (Delta-state), not by status code
    if bv.status in (401, 403, 404):
        verdict, why = "CLEAN", f"B enforced-denied ({bv.status})"
    elif MARKER in bv.body:
        verdict, why = "FINDING", f"B (status {bv.status}) reproduced A's private marker -> BOLA proven"
    elif bv.status == 200:
        verdict, why = "ABSTAIN", "B got 200 but marker ABSENT -> no proof -> no claim"
    else:
        verdict, why = "CLEAN", f"B status {bv.status}, no leak"
    return {"kind": k["name"], "verdict": verdict, "why": why,
            "object_id": oid, "read_path": read_path,
            "proof": {"owner_value_seen": MARKER in av.body,
                      "attacker_status": bv.status,
                      "attacker_reproduced_value": MARKER in bv.body}}

def main() -> int:
    print("AUTHZ PROBER — interventional Wall-1 engine (real HTTP + Delta-state)")
    print("=" * 72)
    results = [probe_kind(k) for k in KINDS]
    findings = 0
    for r in results:
        tag = {"FINDING": "FIND ", "CLEAN": "CLEAN", "ABSTAIN": "ABST ",
               "SKIP": "SKIP "}[r["verdict"]]
        print(f"  [{tag}] {r['kind']:6s} -> {r['verdict']:8s} | {r['why']}")
        if r["verdict"] == "FINDING":
            findings += 1
            print(f"          PoC: as B -> GET {r['read_path']}  reproduces A's private object")
            print(f"          proof: {json.dumps(r['proof'])}")
    print("=" * 72)
    print(f"confirmed findings: {findings} | kinds tested: {len(results)}")
    print("note: a 200 to B is NEVER a finding; only reproduced private VALUE is.")
    # spec assertions (acceptance test): notes must FIND, cards must be CLEAN
    byname = {r["kind"]: r["verdict"] for r in results}
    assert byname.get("notes") == "FINDING", byname
    assert byname.get("cards") == "CLEAN", byname
    print("[acceptance] notes=FINDING, cards=CLEAN  -> fires on the bug, zero-FP on the secure one.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
