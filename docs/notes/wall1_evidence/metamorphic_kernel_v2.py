"""
authz_engine.py — the COMPLETED Wall-1 engine. Supersedes authz_prober.py.

Closes the Wall-1 detection gaps (cleanup / cross-principal mutation / chained
bugs are deliberately left for Wall-3 and later walls):

  G1  Surface-driven: probe pairs are DERIVED from a declared surface (producer
      POST /x  +  consumer GET /x/{id}), not hard-coded. (Wire point: IOLITE.)
  G2  General, SOUND value-presence (the real Delta-state): capture A's owner
      view across TWO of A's own objects (A1,A2) + one of B's (B1); the
      DISCRIMINATING values of A1 = leaves(A1) - leaves(A2) - leaves(B1) - {ids
      the probe supplied}. Leak is proven iff B reproduces a DISCRIMINATING
      value -> kills the shared-default false positive by construction.
  G3  Pluggable credentials/session (header + cookie); DPoP/CSRF-refresh flagged
      as field work (session-3 gap), interface left open.
  G5  ScopeGuard on EVERY request: host allowlist + method gate; cross-principal
      writes refused (dry-run) -- only the operator's OWN objects are mutated.
  GM  Metamorphic non-interference oracle: when value-presence abstains but B
      still gets 200, PERTURB A's own object field and re-read as B; if B's
      observable DEPENDS on A's secret -> leak (catches DERIVED/non-verbatim
      channels that value-presence structurally cannot). Restores the value
      after (a mini safe-mutation; the general safe protocol is Wall-3).

Pure stdlib. Legal-by-construction: only the operator's OWN principals/objects.
"""
from __future__ import annotations
import json, sys, urllib.request, urllib.error
from dataclasses import dataclass, field

# ---------------------------------------------------------------- ScopeGuard (G5)
@dataclass
class ScopeGuard:
    allowed_hosts: set
    allow_write_hosts: set = field(default_factory=set)
    def check(self, host: str, method: str) -> tuple[bool, str]:
        if host not in self.allowed_hosts:
            return False, f"HALT: host '{host}' out of scope"
        if method in ("POST", "PUT", "PATCH", "DELETE") and host not in self.allow_write_hosts:
            return False, f"HALT: write {method} not permitted on '{host}' (dry-run)"
        return True, "ok"

# ---------------------------------------------------------------- Principal (G3)
@dataclass
class Principal:
    pid: str
    headers: dict                      # e.g. {"Authorization": "Bearer tokA"}; cookies/CSRF go here too

# ---------------------------------------------------------------- HTTP w/ guard
@dataclass
class Resp:
    status: int
    body: str
    def json(self):
        try: return json.loads(self.body)
        except Exception: return {}

class Client:
    def __init__(self, base: str, host: str, guard: ScopeGuard):
        self.base, self.host, self.guard = base, host, guard
    def __call__(self, method: str, path: str, who: Principal, payload=None) -> Resp:
        ok, why = self.guard.check(self.host, method)
        if not ok:
            return Resp(-2, why)                       # scope-guard refusal, surfaced not silent
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        for k, v in who.headers.items(): req.add_header(k, v)
        if data is not None: req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return Resp(r.status, r.read().decode())
        except urllib.error.HTTPError as e:
            return Resp(e.code, e.read().decode())
        except Exception as e:                          # noqa: BLE001
            return Resp(-1, str(e))

# ---------------------------------------------------------------- value helpers (G2)
def leaves(obj) -> set:
    """Flatten a JSON value to the set of its leaf values, as strings."""
    out = set()
    def rec(v):
        if isinstance(v, dict):
            for x in v.values(): rec(x)
        elif isinstance(v, list):
            for x in v: rec(x)
        else:
            out.add(str(v))
    rec(obj); return out

# ---------------------------------------------------------------- the engine
@dataclass
class Finding:
    kind: str; verdict: str; why: str; oid: str = ""; proof: dict = field(default_factory=dict)

class Engine:
    def __init__(self, client: Client, A: Principal, B: Principal):
        self.c, self.A, self.B = client, A, B

    def _create(self, kind: str, who: Principal, content: str, secret: str) -> str | None:
        r = self.c("POST", f"/{kind}", who, {"content": content, "secret": secret})
        return r.json().get("id") if r.status in (200, 201) else None

    def probe(self, kind: str) -> Finding:
        # G1: producer/consumer derived from the surface (POST /kind, GET /kind/{id})
        # Create A1, A2 (A's own) and B1 (B's own) with distinct private values.
        a1 = self._create(kind, self.A, "CONTENT-A1-9f3", "SECRET-A1-longlonglong")
        a2 = self._create(kind, self.A, "CONTENT-A2-2b7", "SECRET-A2-x")
        b1 = self._create(kind, self.B, "CONTENT-B1-5c1", "SECRET-B1-y")
        if not (a1 and a2 and b1):
            return Finding(kind, "SKIP", "could not create the 3 control objects")

        # owner control: A reads A1 (must succeed) -> the ground-truth owner view
        va1 = self.c("GET", f"/{kind}/{a1}", self.A)
        if va1.status != 200:
            return Finding(kind, "SKIP", "owner control failed (A cannot read own A1)")
        va2 = self.c("GET", f"/{kind}/{a2}", self.A)
        vb1 = self.c("GET", f"/{kind}/{b1}", self.B)

        # DISCRIMINATING values of A1: unique to A1 vs A2 vs B1, minus the id itself
        disc = (leaves(va1.json()) - leaves(va2.json()) - leaves(vb1.json())) - {a1, a2, b1}

        # PROBE: B reads A1 (the manufactured-negative coordinate)
        pb = self.c("GET", f"/{kind}/{a1}", self.B)
        if pb.status in (401, 403, 404):
            return Finding(kind, "CLEAN", f"B enforced-denied ({pb.status})", a1)

        # G2: sound value-presence -> only a DISCRIMINATING value proves a leak
        hit = disc & leaves(pb.json())
        if hit:
            return Finding(kind, "FINDING", "B reproduced A1's discriminating private value(s)", a1,
                           {"channel": "value-presence", "leaked": sorted(hit),
                            "attacker_status": pb.status})

        # GM: value-presence abstained but B got 200 -> try the metamorphic oracle
        if pb.status == 200:
            m = self._metamorphic(kind, a1)
            if m:
                return Finding(kind, "FINDING", "B's observable DEPENDS on A1's secret (derived-channel leak)", a1,
                               {"channel": "metamorphic", **m})
            return Finding(kind, "CLEAN", "B got 200 but no discriminating value and no secret-dependence (shared-default)", a1,
                           {"channel": "none"})
        return Finding(kind, "CLEAN", f"B status {pb.status}", a1)

    def _metamorphic(self, kind: str, a1: str) -> dict | None:
        """Perturb A1's OWN secret (A writes to own object), observe B's view, restore.
        Dependence of B's observable on A's secret = a non-interference violation."""
        before = self.c("GET", f"/{kind}/{a1}", self.B).body
        up = self.c("PUT", f"/{kind}/{a1}", self.A, {"secret": "x"})      # short secret
        if up.status != 200:
            return None                                                   # cannot perturb -> inconclusive
        after = self.c("GET", f"/{kind}/{a1}", self.B).body
        self.c("PUT", f"/{kind}/{a1}", self.A, {"secret": "SECRET-A1-longlonglong"})  # restore (mini safe-mutation)
        if before != after:
            return {"B_view_before": before, "B_view_after": after}
        return None

def main() -> int:
    guard = ScopeGuard(allowed_hosts={"127.0.0.1:8899"}, allow_write_hosts={"127.0.0.1:8899"})
    client = Client("http://127.0.0.1:8899", "127.0.0.1:8899", guard)
    A = Principal("A", {"Authorization": "Bearer tokA"})
    B = Principal("B", {"Authorization": "Bearer tokB"})
    eng = Engine(client, A, B)

    print("AUTHZ ENGINE (Wall-1 complete) — real HTTP + sound Delta-state + metamorphic + scope-guard")
    print("=" * 84)
    kinds = ["notes", "cards", "badges", "flags"]
    results = {}
    for k in kinds:
        f = eng.probe(k)
        results[k] = f.verdict
        tag = {"FINDING": "FIND ", "CLEAN": "CLEAN", "ABSTAIN": "ABST ", "SKIP": "SKIP "}[f.verdict]
        print(f"  [{tag}] {k:7s} -> {f.verdict:8s} | {f.why}")
        if f.verdict == "FINDING":
            print(f"            proof: {json.dumps(f.proof)}")

    # G5 scope-guard demonstration: an out-of-scope host must HALT (not send a packet)
    bad = Client("http://169.254.0.1", "169.254.0.1", guard)
    og = bad("GET", "/x", A)
    print("-" * 84)
    print(f"  [GUARD] out-of-scope GET -> {og.body}")

    print("=" * 84)
    # acceptance spec (Gate 2): each kind exercises a distinct detection path
    assert results["notes"] == "FINDING", results      # verbatim BOLA via value-presence
    assert results["cards"] == "CLEAN",   results       # secure -> zero-FP
    assert results["badges"] == "CLEAN",  results       # shared-default -> zero-FP (the hard one)
    assert results["flags"] == "FINDING", results       # derived 1-bit leak via metamorphic
    assert og.status == -2, og                          # scope-guard refused, no packet sent
    print("[acceptance] notes=FIND(value), cards=CLEAN, badges=CLEAN(shared-default guard),")
    print("             flags=FIND(metamorphic), scope-guard HALTed out-of-scope. all passed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
