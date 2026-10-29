"""
wall3_bench_runner.py — generalized HTTP write-BOLA engine, scored on the FAIR
labeled benchmark (wall3_benchmark_app.py). Produces a confusion matrix +
precision / recall / safety against ground truth (GET /labels).

Flow per op: gate0 static screen -> gate1 empirical rehearsal on a sacrificial
own object -> confirm (B acts on A's object, owner read-back, op-specific change
detection) -> restore via inverse -> verify. Zero target-specific code beyond the
op table (which a real run derives from the surface model / OpenAPI).
"""
from __future__ import annotations
import json, sys, urllib.request, urllib.error, uuid

BASE = "http://127.0.0.1:8911"
TOK = {"A": "tokA", "B": "tokB"}
DANGER = ("pay", "money", "charge", "transfer", "email", "sms", "notify",
          "publish", "invite", "webhook", "send", "wire", "payout")

def http(method, path, who=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if who: req.add_header("Authorization", "Bearer " + TOK[who])
    if data is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try: j = json.loads(e.read().decode() or "{}")
        except Exception: j = {}
        return e.code, j
    except Exception as e:                         # noqa: BLE001
        return -1, {"e": str(e)}

def create(who): return http("POST", "/obj", who)[1].get("id")
def readback(oid, who): st, j = http("GET", f"/obj/{oid}", who); return j if st == 200 else None

# --- op table (in a real run: derived from IOLITE surface / OpenAPI) ------------
def OPS(nonce):
    mk = f"HACK-{nonce}"
    return [
        {"n":"update_field","mut":("PUT","/obj/{id}/field",{"value":mk}),"detect":("content",mk),"inv":("field",)},
        {"n":"set_role","mut":("PUT","/obj/{id}/role",{"value":"admin"}),"detect":("role","admin"),"inv":("role",)},
        {"n":"change_owner","mut":("PUT","/obj/{id}/owner",{"value":"B"}),"detect":("owner","B"),"inv":("owner",)},
        {"n":"soft_delete","mut":("DELETE","/obj/{id}/soft",None),"detect":("deleted",None),"inv":("undelete",)},
        {"n":"hard_delete","mut":("DELETE","/obj/{id}/hard",None),"detect":("deleted",None),"inv":("undelete",)},
        {"n":"advance_workflow","mut":("POST","/obj/{id}/advance",None),"detect":("state","done"),"inv":("none",)},
        {"n":"notify","mut":("POST","/obj/{id}/notify",None),"detect":("state","done"),"inv":("none",)},
        {"n":"update_secure","mut":("PUT","/obj/{id}/secure",{"value":mk}),"detect":("content",mk),"inv":("field",)},
        {"n":"update_noop","mut":("PUT","/obj/{id}/noop",{"value":mk}),"detect":("content",mk),"inv":("field",)},
        {"n":"update_shared","mut":("PUT","/obj/{id}/shared",{"value":mk}),"detect":("content",mk),"inv":("field",)},
    ]

def screen(op):
    hay = (op["n"] + " " + op["mut"][1]).lower()
    return next((k for k in DANGER if k in hay), None)

def apply_mut(op, oid, who):
    m, path, body = op["mut"]
    return http(m, path.replace("{id}", oid), who, body)

def invert(op, oid, before):
    kind = op["inv"][0]
    if kind == "field":  http("PUT", f"/obj/{oid}/field", "A", {"value": before["content"]})
    elif kind == "role": http("PUT", f"/obj/{oid}/role", "A", {"value": before["role"]})
    elif kind == "owner":http("PUT", f"/obj/{oid}/owner", "A", {"value": before["owner"]})
    elif kind == "undelete": http("POST", f"/obj/{oid}/undelete", "A")

def changed(op, before, after):
    key, val = op["detect"]
    if key == "deleted": return after is None
    if after is None: return False
    return after.get(key) == val

def rehearse(op):
    sid = create("A"); before = readback(sid, "A")
    apply_mut(op, sid, "A")
    invert(op, sid, before)
    after = readback(sid, "A")
    reverted = (after == before) or (after is not None and before is not None
                                     and after.get(op["detect"][0]) == before.get(op["detect"][0]))
    http("DELETE", f"/obj/{sid}/hard", "A")     # purge our disposable object
    return reverted

def run():
    nonce = uuid.uuid4().hex[:6]
    _, labels = http("GET", "/labels")
    results = {}
    created = []
    for op in OPS(nonce):
        name = op["n"]
        if screen(op):                                   # gate 0
            results[name] = "REFUSED"; continue
        if not rehearse(op):                             # gate 1 (empirical)
            results[name] = "REFUSED"; continue
        aid = create("A"); created.append(aid)
        before = readback(aid, "A")
        apply_mut(op, aid, "B")                          # attacker B acts on A's object
        after = readback(aid, "A")
        vio = changed(op, before, after)
        invert(op, aid, before)                          # restore
        results[name] = "FINDING" if vio else "CLEAN"
    # cleanup all test objects
    for oid in created: http("DELETE", f"/obj/{oid}/hard", "A")
    _, ext = http("GET", "/_external")

    # ---- confusion matrix vs ground truth ----
    tp = fp = fn = tn = refused = 0
    rows = []
    for name, lab in labels.items():
        v = results.get(name, "MISSING"); truth = lab["truth"]
        if truth == "VULN_FINDABLE":
            if v == "FINDING": tp += 1; outcome = "TP"
            else: fn += 1; outcome = "FN (missed a findable vuln!)"
        elif truth == "VULN_REFUSE_SAFETY":
            outcome = "REFUSED-safely" if v == "REFUSED" else f"!! expected REFUSE got {v}"
            refused += v == "REFUSED"
        elif truth == "VULN_MISS_BYDESIGN":
            outcome = "miss-by-design (honest FN)" if v in ("CLEAN", "REFUSED") else f"unexpected {v}"
            fn += v not in ("FINDING",)  and 0  # not counted against precision; it's a known class gap
        elif truth == "SECURE":
            if v == "FINDING": fp += 1; outcome = "FP !!"
            else: tn += 1; outcome = "TN"
        elif truth == "DECOY":
            if v == "FINDING": fp += 1; outcome = "FP !! (decoy flagged)"
            else: tn += 1; outcome = "TN"
        rows.append((name, lab["taxonomy"], v, truth, outcome))

    print("WALL-3 FAIR BENCHMARK (real-distribution; write-side authz)")
    print("=" * 90)
    for n, tax, v, truth, out in rows:
        print(f"  {n:16s} {tax:32s} verdict={v:8s} truth={truth:18s} -> {out}")
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec_find = tp / (tp + fn) if (tp + fn) else 0.0
    print("-" * 90)
    print(f"  TP={tp} FP={fp} TN={tn} FN(findable)={fn} refused-for-safety={refused}")
    print(f"  PRECISION = {prec:.3f}   (false positives on secure+decoys must be 0 -> FP={fp})")
    print(f"  RECALL (on findable subset) = {rec_find:.3f}")
    print(f"  SAFETY: external effects during whole run = {ext['count']} (must be 0); "
          f"test objects left = {[o for o in created if readback(o,'A')]} ")
    print("=" * 90)
    assert fp == 0, "FALSE POSITIVE — precision broken"
    assert tp == 4, f"expected 4 findable write-authz bugs, got {tp}"
    assert ext["count"] == 0, "HARM: external effect occurred"
    assert all(readback(o, "A") is None for o in created), "litter left"
    print("PASS: precision 1.000, all 4 findable write-authz classes caught, unsafe ops")
    print("      refused, by-design miss acknowledged, zero harm, zero litter.")

if __name__ == "__main__":
    sys.exit(run())
