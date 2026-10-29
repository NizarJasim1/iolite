"""
wall3_sweep.py — Wall-3 qualitative leap: EMPIRICAL safety + FULL mutation-surface sweep.

Two breakthroughs over the single-op safety kernel:
  (1) EMPIRICAL reversibility/side-effect REHEARSAL. We no longer trust an a-priori
      "is this reversible?" label (undecidable on a black box). For each op we
      REHEARSE it on a SACRIFICIAL object WE create and own: apply -> attempt the
      inverse -> verify exact restoration -> watch OOB/external channels. Only ops
      that EMPIRICALLY revert with no external effect are promoted to real use.
      (This converts the classification oracle into a sound measurement on
      disposable own-data; residual = effects that only trigger on other data.)
  (2) FULL SWEEP across the write-side authz TAXONOMY: write-BOLA, delete-BOLA,
      BOPLA-write (mass-assignment: role/owner escalation). Budgeted, blast-radius
      capped, global write-ahead log, AUTO-CLEANUP of every test object created
      (solves the Wall-1 deferred cleanup), and a transparent MUTATION LEDGER.

In-process deterministic mock so side effects / crashes are observable. Next step
is the same engine over HTTP against an independent target. Pure stdlib.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

# --------------------------------------------------------------- the target (mock)
class Mock:
    def __init__(self):
        self.objs: dict = {}; self.trash: dict = {}; self._n = 0
        self.external: list = []          # harmful external effects (money/email) — must stay []
        self.audit: list = []             # benign audit trail (expected; not harmful)
    def create(self, owner):
        self._n += 1; oid = f"o{self._n}"
        self.objs[oid] = {"id": oid, "owner": owner, "field": "init", "role": "user"}
        self.audit.append(("create", oid)); return oid
    def read(self, viewer, oid):          # BOLA read (no owner check)
        return dict(self.objs[oid]) if oid in self.objs else None
    def set_field(self, viewer, oid, val):      # BOLA write
        if oid not in self.objs: return 404
        self.objs[oid]["field"] = val; self.audit.append(("set_field", oid)); return 200
    def set_role(self, viewer, oid, val):       # BOLA + privileged-property (BOPLA) write
        if oid not in self.objs: return 404
        self.objs[oid]["role"] = val; self.audit.append(("set_role", oid)); return 200
    def set_field_secure(self, viewer, oid, val):   # secure (owner only) -> control
        if self.objs.get(oid, {}).get("owner") != viewer: return 403
        self.objs[oid]["field"] = val; return 200
    def soft_delete(self, viewer, oid):         # reversible delete (undelete exists)
        if oid in self.objs: self.trash[oid] = self.objs.pop(oid); return 200
        return 404
    def undelete(self, viewer, oid):
        if oid in self.trash: self.objs[oid] = self.trash.pop(oid); return 200
        return 404
    def hard_delete(self, viewer, oid):         # IRREVERSIBLE purge (no undelete)
        self.objs.pop(oid, None); self.trash.pop(oid, None); return 200
    def send_money(self, viewer, oid, amt):     # EXTERNAL side effect
        self.external.append((viewer, amt)); return 200

class Rev(Enum):
    REVERSIBLE = "empirically-reversible"
    IRREVERSIBLE = "empirically-irreversible-or-external"

@dataclass
class Op:
    name: str
    taxonomy: str                       # write-BOLA | delete-BOLA | BOPLA-write
    apply: callable                     # (mock, viewer, oid, payload) -> status
    inverse: callable                   # (mock, oid, before) -> None  (best-effort restoration)
    payload: str = ""
    changed: callable = None            # (before_obj, after_obj) -> bool : did the security property change?

# --------------------------------------------------------------- global WAL + ledger
@dataclass
class Sweep:
    wal: list = field(default_factory=list)
    ledger: list = field(default_factory=list)      # transparent record of every mutation+restore
    created: list = field(default_factory=list)     # test objects to clean up
    mutations: int = 0

# --------------------------------------------------------------- the engine
class Engine:
    def __init__(self, mock: Mock, max_mutations=50):
        self.m = mock; self.max_mutations = max_mutations; self.s = Sweep()

    # (0) STATIC pre-screen — NON-EXECUTING. You cannot rehearse an external effect
    # without causing it (the measurement IS the harm), so refuse dangerous
    # semantics BEFORE touching anything. Rehearsal is the 2nd line of defense.
    DANGER = ("pay", "money", "charge", "transfer", "refund", "send", "email",
              "sms", "notify", "publish", "invite", "webhook", "wire", "payout")
    def static_screen(self, op: Op) -> tuple[bool, str]:
        hay = f"{op.name} {op.taxonomy}".lower()
        for kw in self.DANGER:
            if kw in hay:
                return False, f"static screen: '{kw}' indicates a possible external effect"
        return True, "passed static screen"

    # (1) EMPIRICAL rehearsal on a sacrificial OWN object -----------------------
    def rehearse(self, op: Op) -> tuple[Rev, str]:
        sid = self.m.create("ME"); self.s.created.append(sid)
        before = self.m.read("ME", sid)
        ext0 = len(self.m.external)
        op.apply(self.m, "ME", sid, op.payload or "REHEARSE")
        ext_effect = len(self.m.external) > ext0
        op.inverse(self.m, sid, before)                      # attempt the candidate inverse
        after_inv = self.m.read("ME", sid)
        reverted = (after_inv == before)
        self.m.hard_delete("ME", sid)                        # purge our disposable object
        if ext_effect:   return Rev.IRREVERSIBLE, "external/OOB effect observed during rehearsal"
        if not reverted: return Rev.IRREVERSIBLE, "candidate inverse did not exactly restore"
        return Rev.REVERSIBLE, "rehearsal reverted cleanly, no external effect"

    # safe, write-ahead mutation with verified restore --------------------------
    def _safe_mutate(self, op, oid, before):
        if self.s.mutations >= self.max_mutations:
            return None, "blast-radius budget exhausted"
        self.s.wal.append({"op": op.name, "oid": oid, "restore": before, "done": False})
        self.s.mutations += 1
        op.apply(self.m, "B", oid, op.payload or "HACK-BY-B")   # attacker B acts on A's object
        after = self.m.read("A", oid)                            # Δstate read-back as OWNER A
        op.inverse(self.m, oid, before)                          # restore
        self.s.wal[-1]["done"] = True
        restored = self.m.read("A", oid)
        self.s.ledger.append({"op": op.name, "object": oid,
                              "mutated_as": "B", "restored_ok": restored == before})
        if restored != before:
            return after, "HALT: restore unverified — state left altered"
        return after, "ok"

    def test_op(self, op: Op) -> dict:
        ok, why = self.static_screen(op)                 # gate 0: non-executing screen
        if not ok:
            return {"op": op.name, "taxonomy": op.taxonomy, "verdict": "REFUSED", "why": why}
        rev, why = self.rehearse(op)                      # gate 1: empirical rehearsal
        if rev == Rev.IRREVERSIBLE:
            return {"op": op.name, "taxonomy": op.taxonomy, "verdict": "REFUSED", "why": why}
        aid = self.m.create("A"); self.s.created.append(aid)
        before = self.m.read("A", aid)
        after, status = self._safe_mutate(op, aid, before)
        if status.startswith("HALT"):
            return {"op": op.name, "taxonomy": op.taxonomy, "verdict": "HALT", "why": status}
        if after is None and status != "ok":
            return {"op": op.name, "taxonomy": op.taxonomy, "verdict": "SKIP", "why": status}
        violated = op.changed(before, after)
        return {"op": op.name, "taxonomy": op.taxonomy,
                "verdict": "FINDING" if violated else "CLEAN",
                "why": ("B changed A's object; confirmed by owner read-back, then restored"
                        if violated else "attacker action did not persist")}

    def cleanup(self) -> int:
        for oid in self.s.created:
            self.m.hard_delete("ME", oid)
        n = len(self.s.created); self.s.created = []; return n

# --------------------------------------------------------------- the surface (swept)
def inv_setfield(m, oid, before): m.set_field("ME", oid, before["field"]) if before else None
def inv_setrole(m, oid, before):  m.set_role("ME", oid, before["role"]) if before else None
def inv_undelete(m, oid, before): m.undelete("ME", oid)
def inv_none(m, oid, before):     pass

SURFACE = [
    Op("set_field", "write-BOLA", lambda m,v,o,p: m.set_field(v,o,p), inv_setfield,
       payload="HACK-BY-B", changed=lambda b,a: bool(a) and a["field"] == "HACK-BY-B"),
    Op("set_role", "BOPLA-write (mass-assignment)", lambda m,v,o,p: m.set_role(v,o,p), inv_setrole,
       payload="admin", changed=lambda b,a: bool(a) and a["role"] == "admin"),
    Op("soft_delete", "delete-BOLA", lambda m,v,o,p: m.soft_delete(v,o), inv_undelete,
       changed=lambda b,a: a is None),
    Op("hard_delete", "delete-BOLA", lambda m,v,o,p: m.hard_delete(v,o), inv_undelete,
       changed=lambda b,a: a is None),                         # rehearsal will REFUSE this
    Op("send_money", "external", lambda m,v,o,p: m.send_money(v,o,1000), inv_none,
       changed=lambda b,a: True),                               # rehearsal will REFUSE this
    Op("set_field_secure", "write-BOLA", lambda m,v,o,p: m.set_field_secure(v,o,p), inv_setfield,
       payload="HACK-BY-B", changed=lambda b,a: bool(a) and a["field"] == "HACK-BY-B"),  # secure -> CLEAN
]

def main():
    m = Mock(); eng = Engine(m)
    results = [eng.test_op(op) for op in SURFACE]
    cleaned = eng.cleanup()

    print("WALL-3 SWEEP — empirical safety + full write-surface comb")
    print("=" * 78)
    nf = 0
    for r in results:
        tag = {"FINDING":"FIND ","CLEAN":"CLEAN","REFUSED":"REFUS","HALT":"HALT ","SKIP":"SKIP "}[r["verdict"]]
        print(f"  [{tag}] {r['op']:16s} {r['taxonomy']:28s} -> {r['verdict']}")
        print(f"          {r['why']}")
        nf += r["verdict"] == "FINDING"
    print("-" * 78)
    print(f"findings: {nf} | ops swept: {len(results)} | mutations performed: {eng.s.mutations} "
          f"| test objects cleaned up: {cleaned} (litter=0)")
    print(f"external/harmful effects during whole sweep: {len(m.external)}  (must be 0)")
    print("mutation ledger (transparent, all restored):")
    for e in eng.s.ledger:
        print(f"    {e}")
    # acceptance
    by = {r["op"]: r["verdict"] for r in results}
    assert by["set_field"] == "FINDING", by           # write-BOLA
    assert by["set_role"] == "FINDING", by            # BOPLA-write / mass-assignment
    assert by["soft_delete"] == "FINDING", by         # delete-BOLA (reversible -> safe to confirm)
    assert by["hard_delete"] == "REFUSED", by         # empirically irreversible -> fail-safe
    assert by["send_money"] == "REFUSED", by          # empirically external -> fail-safe
    assert by["set_field_secure"] == "CLEAN", by      # zero-FP
    assert len(m.external) == 0, "HARM: external effect occurred"
    assert all(e["restored_ok"] for e in eng.s.ledger), "a mutation was not restored"
    assert cleaned >= 1 and len(m.objs) == 0, ("litter left", m.objs)
    print("=" * 78)
    print("all assertions passed: swept 3 write-authz classes, refused unsafe ops EMPIRICALLY,")
    print("zero harm, every mutation restored, every test object cleaned up.")

if __name__ == "__main__":
    main()
