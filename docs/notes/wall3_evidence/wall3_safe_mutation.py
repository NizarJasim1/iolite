"""
wall3_safe_mutation.py — proof-of-mechanism for the Wall-3 SAFE-MUTATION core.

Thesis: refine the fail-safe (RL5) from "suppress ALL mutations" to "suppress only
provably-UNSAFE mutations", so write-side BOLA (the ~42% action-level majority)
can be CONFIRMED by a real Δstate with ZERO net harm. Enabled by:
  (1) a reversibility classifier (RESTORE / COMPENSATE / IRREVERSIBLE),
  (2) own-principal consent  (we only ever mutate objects WE own),
  (3) a write-ahead compensating saga (snapshot -> WAL -> mutate -> confirm ->
      restore -> verify; a crash is recovered from the WAL),
  (4) a conservative external-side-effect gate (unknown effect => IRREVERSIBLE).

In-process mock (no HTTP) so a crash can be injected DETERMINISTICALLY and the
restore/no-litter guarantee verified. The live-HTTP confirmation is the next step.
Pure stdlib, deterministic.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

# ----------------------------------------------------------- the target (mock)
class Mock:
    """A tiny resource store. Some ops are BOLA (no owner check), one is secure,
    some are irreversible / externally-effectful."""
    def __init__(self):
        self.obj = {"id": "A1", "owner": "A", "field": "ORIGINAL-A"}
        self.deleted = False
        self.external_calls: list[str] = []     # money/email/etc. — must stay empty
    def read(self, viewer):                       # BOLA read (any viewer)
        return None if self.deleted else dict(self.obj)
    def put_field_bola(self, viewer, value):      # BOLA write: no owner check
        if self.deleted: return 404
        self.obj["field"] = value; return 200
    def put_field_secure(self, viewer, value):    # secure write: owner only
        if self.deleted: return 404
        if viewer != self.obj["owner"]: return 403
        self.obj["field"] = value; return 200
    def hard_delete(self, viewer):                # IRREVERSIBLE (no restore API)
        self.deleted = True; return 200
    def send_money(self, viewer, amt):            # EXTERNAL side effect
        self.external_calls.append(f"pay:{amt}"); return 200

# ----------------------------------------------------------- reversibility model
class Rev(Enum):
    RESTORE = "reversible-by-restore"       # snapshot a field, write it back
    COMPENSATE = "reversible-by-inverse"    # app provides an inverse affordance
    IRREVERSIBLE = "irreversible-or-external"

@dataclass
class OpSpec:
    name: str
    apply: callable                 # (mock, viewer, value) -> status
    reversibility: Rev
    snapshot: callable = None       # (mock) -> saved state   (for RESTORE)
    restore: callable = None        # (mock, saved) -> None    (for RESTORE/COMPENSATE)
    may_have_external_effect: bool = True   # CONSERVATIVE default: unknown => unsafe

# ----------------------------------------------------------- write-ahead log
@dataclass
class WAL:
    entries: list = field(default_factory=list)
    def record(self, op_name, saved):
        self.entries.append({"op": op_name, "restore": saved, "done": False})
    def mark_done(self, i): self.entries[i]["done"] = True
    def pending(self):      return [(i, e) for i, e in enumerate(self.entries) if not e["done"]]

class Crash(Exception):
    pass

# ----------------------------------------------------------- the safe-mutation txn
@dataclass
class Result:
    verdict: str
    why: str
    net_harm: bool = False

class SafeMutator:
    def __init__(self, mock: Mock, owned_objects: set, wal: WAL):
        self.m, self.owned, self.wal = mock, owned_objects, wal

    def _refuse(self, op, reason) -> Result:
        return Result("REFUSED", f"{op.name}: {reason} (fail-safe to inaction)")

    def confirm_write_bola(self, op: OpSpec, attacker: str, owner: str,
                           payload: str, inject_crash=False) -> Result:
        # (2) consent/ownership gate: only mutate state we OWN
        if self.m.obj["id"] not in self.owned:
            return self._refuse(op, "target object is not operator-owned")
        # (1)+(4) reversibility + external-effect gate
        if op.reversibility == Rev.IRREVERSIBLE or op.may_have_external_effect:
            return self._refuse(op, f"classified {op.reversibility.value} / external-effect")
        # (3) saga: snapshot -> WAL (BEFORE mutate) -> mutate -> confirm -> restore -> verify
        saved = op.snapshot(self.m)
        self.wal.record(op.name, saved)
        idx = len(self.wal.entries) - 1
        status = op.apply(self.m, attacker, payload)        # the attacker's write
        if inject_crash:
            raise Crash("process died after mutation, before restore")
        # Δstate confirmation: read back as the OWNER — did the attacker's write persist?
        after = self.m.read(owner)
        violated = bool(after and after.get("field") == payload and attacker != owner)
        # restore (compensate) and verify
        op.restore(self.m, saved); self.wal.mark_done(idx)
        restored = self.m.read(owner)
        if restored != saved_view(saved, self.m):
            return Result("HALT", f"{op.name}: restore unverified — state left altered!", net_harm=True)
        if violated:
            return Result("FINDING", f"write-BOLA: {attacker} wrote {owner}'s object; confirmed by "
                                     f"owner read-back, then restored (net-zero).")
        return Result("CLEAN", f"{op.name}: attacker write did not persist (status {status})")

    def recover(self) -> int:
        """Crash recovery: replay any pending WAL restores. Returns #restored."""
        n = 0
        for i, e in self.wal.pending():
            # for RESTORE ops the saved state fully defines the row
            self.m.obj = dict(e["restore"]["obj"]); self.m.deleted = e["restore"]["deleted"]
            self.wal.mark_done(i); n += 1
        return n

def saved_view(saved, mock):
    """What read() would return for the saved snapshot (owner view)."""
    return None if saved["deleted"] else dict(saved["obj"])

# ----------------------------------------------------------- scenarios
def snap(m: Mock):     return {"obj": dict(m.obj), "deleted": m.deleted}
def restore(m, s):     m.obj = dict(s["obj"]); m.deleted = s["deleted"]

def main():
    rows = []

    # Case A: reversible field-write BOLA (internal, no external effect) -> CONFIRM + RESTORE
    m = Mock(); wal = WAL()
    op_rev = OpSpec("put_field", lambda mk, v, val: mk.put_field_bola(v, val),
                    Rev.RESTORE, snapshot=snap, restore=restore, may_have_external_effect=False)
    sm = SafeMutator(m, owned_objects={"A1"}, wal=wal)
    r = sm.confirm_write_bola(op_rev, attacker="B", owner="A", payload="HACKED-BY-B")
    rows.append(("A reversible write-BOLA", r.verdict, r.why))
    assert r.verdict == "FINDING" and not r.net_harm, r
    assert m.obj["field"] == "ORIGINAL-A", ("NOT RESTORED", m.obj)      # net-zero harm

    # Case B: irreversible op (hard delete) -> REFUSED, nothing performed
    m = Mock(); wal = WAL()
    op_del = OpSpec("hard_delete", lambda mk, v, val: mk.hard_delete(v),
                    Rev.IRREVERSIBLE, may_have_external_effect=False)
    sm = SafeMutator(m, {"A1"}, wal)
    r = sm.confirm_write_bola(op_del, "B", "A", payload="")
    rows.append(("B irreversible delete", r.verdict, r.why))
    assert r.verdict == "REFUSED" and m.deleted is False, r               # never performed

    # Case B2: external side effect (send money) -> REFUSED even if "reversible"-looking
    m = Mock(); wal = WAL()
    op_pay = OpSpec("send_money", lambda mk, v, val: mk.send_money(v, val),
                    Rev.RESTORE, snapshot=snap, restore=restore, may_have_external_effect=True)
    sm = SafeMutator(m, {"A1"}, wal)
    r = sm.confirm_write_bola(op_pay, "B", "A", payload="100")
    rows.append(("B2 external-effect op", r.verdict, r.why))
    assert r.verdict == "REFUSED" and m.external_calls == [], r           # no external call made

    # Case C: CRASH mid-transaction on a reversible write -> WAL recovery, no litter
    m = Mock(); wal = WAL()
    sm = SafeMutator(m, {"A1"}, wal)
    try:
        sm.confirm_write_bola(op_rev, "B", "A", payload="HACKED-MIDCRASH", inject_crash=True)
    except Crash:
        pass
    assert m.obj["field"] == "HACKED-MIDCRASH", "crash left mutation (expected pre-restore)"
    restored = sm.recover()                                               # recovery replays WAL
    rows.append(("C crash + WAL recovery", f"restored={restored}", "state returned to original"))
    assert m.obj["field"] == "ORIGINAL-A", ("RECOVERY FAILED", m.obj)     # no corruption/litter

    # Case D: secure endpoint -> attacker write denied -> CLEAN (zero-FP)
    m = Mock(); wal = WAL()
    op_sec = OpSpec("put_field_secure", lambda mk, v, val: mk.put_field_secure(v, val),
                    Rev.RESTORE, snapshot=snap, restore=restore, may_have_external_effect=False)
    sm = SafeMutator(m, {"A1"}, wal)
    r = sm.confirm_write_bola(op_sec, "B", "A", payload="HACKED-BY-B")
    rows.append(("D secure write", r.verdict, r.why))
    assert r.verdict == "CLEAN" and m.obj["field"] == "ORIGINAL-A", r

    print("WALL-3 SAFE-MUTATION PROOF OF MECHANISM")
    print("-" * 74)
    for name, v, why in rows:
        tag = {"FINDING": "FIND ", "CLEAN": "CLEAN", "REFUSED": "REFUS", "restored=1": "RECOV"}.get(v, "INFO ")
        print(f"  [{tag}] {name:28s} -> {v}")
        print(f"          {why}")
    print("-" * 74)
    print("reversible write-BOLA CONFIRMED then RESTORED (net-zero); irreversible &")
    print("external ops REFUSED; crash RECOVERED via WAL (no litter); secure=CLEAN.")
    print("all assertions passed.")

if __name__ == "__main__":
    main()
