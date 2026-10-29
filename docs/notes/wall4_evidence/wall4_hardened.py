"""
wall4_hardened.py — final Wall-4 hardening, from new angles:
  A1 STABILITY VOTING on every probe (flaky target -> ABSTAIN, never a flaky FP).
  A2 DECLARED-PRIVACY ANCHOR: intent-deny is established by the app's own
     visibility=private declaration (verified from the owner), NOT by "a control
     was denied". This is what lets us catch a UNIVERSAL BOLA on a private object
     while NOT flagging an object the app designs to be public/auto-shared.
  A3 MULTI-CONTROL AGREEMENT: ≥2 no-relationship controls must agree; disagreement
     => observer-dependent/adversarial target => ABSTAIN + flag.
  A4 BUG-BOUNTY: dossier carries blast-radius + expected-value (EV) ranking.
Decision stays H-independent and zero-FP: any uncertainty resolves to ABSTAIN.
Deterministic (seeded). Proof-of-mechanism, in-process.
"""
from __future__ import annotations
from dataclasses import dataclass

K, QUORUM = 5, 4           # stability: 5 trials, need ≥4 agreeing

@dataclass(frozen=True)
class P:
    pid: str; team: str

A = P("A", "proj1"); B = P("B", "proj1")          # B has a true team relationship to A
D1 = P("D1", "ctlX"); D2 = P("D2", "ctlY")        # matched no-relationship controls we own

def relationship(v: P) -> str | None:
    return "same-team(proj1)" if v.team == "proj1" and v.pid != "A" else None

# ---- target object behaviors (access(viewer, trial) -> bool), + declared visibility
def make_obj(visibility, behavior):
    def access(v: P, t: int) -> bool:
        if behavior == "stable_universal": return True
        if behavior == "stable_secure":    return v.pid == "A" or v.team == "proj1"
        if behavior == "flaky":            return (t % 2 == 0)            # alternates -> unstable
        if behavior == "observer_dependent":                              # D1 in, D2 out (poison)
            return v.pid in ("A", "B", "D1")
        return False
    return {"visibility": visibility, "access": access}

# ---- stability voting (A1)
def stable(obj, v: P):
    votes = sum(obj["access"](v, t) for t in range(K))
    if votes >= QUORUM: return True
    if votes <= K - QUORUM: return False
    return None                              # flaky / no quorum

@dataclass
class V:
    verdict: str; why: str; dossier: dict = None

def decide(attacker: P, obj: dict) -> V:
    # A2: declared-privacy anchor — the intent-deny baseline
    if obj["visibility"] != "private":
        return V("ABSTAIN", "no declared-private anchor (app designs this public/shared) -> cannot establish intent-deny")
    atk = stable(obj, attacker)                                     # A1
    if atk is None:  return V("ABSTAIN", "attacker access is flaky (no quorum)")
    if atk is False: return V("CLEAN", "attacker stably denied")
    c1, c2 = stable(obj, D1), stable(obj, D2)                       # A1 on controls
    if c1 is None or c2 is None:
        return V("ABSTAIN", "control access flaky -> non-deterministic target, refuse to conclude")
    if c1 != c2:                                                    # A3
        return V("ABSTAIN", "controls DISAGREE -> observer-dependent/adversarial target (flagged)")
    control_in = c1
    rel = relationship(attacker)
    if rel and not control_in:
        return V("ABSTAIN", f"benign: '{rel}' is the CAUSE (matched no-relationship controls stably denied)")
    # declared-private + stable attacker-in + (universal OR no-relationship) + stable agreeing controls
    blast = 1000 if control_in else 1          # universal => huge blast radius
    sev = 9.1 if control_in else 7.5
    payout, dup_p = 2500, (0.6 if control_in else 0.2)
    ev = round(payout * (sev / 10) * (1 - dup_p))
    return V("FINDING", "declared-private violated; causal falsification failed (stable, agreeing controls)",
             {"class": "BOLA (API1:2023)", "universal": control_in, "blast_radius": blast,
              "severity": sev, "dup_prob": dup_p, "EV_usd": ev,
              "refuted": ([f"'{rel}' exists but control also got in -> not the cause"] if rel else
                          ["attacker has no relationship"])})

def main():
    cases = [
        ("C1 declared-private + UNIVERSAL bola (B has team rel)", B, make_obj("private", "stable_universal")),
        ("C2 declared-private + secure (team is the cause)",       B, make_obj("private", "stable_secure")),
        ("C3 declared-private + FLAKY target",                     B, make_obj("private", "flaky")),
        ("C4 declared-private + OBSERVER-DEPENDENT target",        B, make_obj("private", "observer_dependent")),
        ("C5 PUBLIC-by-design object (no private anchor)",         B, make_obj("public", "stable_universal")),
    ]
    print("WALL-4 HARDENED (stability + declared-privacy anchor + multi-control + EV)")
    print("=" * 84)
    res = {}
    for name, atk, obj in cases:
        v = decide(atk, obj); res[name] = v.verdict
        print(f"  {name}\n      -> {v.verdict}: {v.why}")
        if v.dossier: print(f"      dossier: {v.dossier}")
    print("=" * 84)
    assert res["C1 declared-private + UNIVERSAL bola (B has team rel)"] == "FINDING"   # caught despite team rel + universal
    assert res["C2 declared-private + secure (team is the cause)"] == "ABSTAIN"         # benign, no FP
    assert res["C3 declared-private + FLAKY target"] == "ABSTAIN"                        # A1: no flaky FP
    assert res["C4 declared-private + OBSERVER-DEPENDENT target"] == "ABSTAIN"           # A3: adversarial
    assert res["C5 PUBLIC-by-design object (no private anchor)"] == "ABSTAIN"            # A2: design-public, not a bug
    print("PROVEN: universal BOLA on a DECLARED-private object is caught (even though the")
    print("        attacker has a team relationship); flaky & observer-dependent targets and")
    print("        design-public objects all ABSTAIN -> zero-FP preserved under non-determinism,")
    print("        adversarial responses, and auto-share design. Dossier ranks by EV.")

if __name__ == "__main__":
    main()
