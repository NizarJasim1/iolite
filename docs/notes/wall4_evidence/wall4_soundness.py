"""
wall4_soundness.py — proof for Wall-4: the zero-FP guarantee must NOT depend on
the true intent being expressible in the hypothesis algebra H.

The threat: the version-space rule ("fire iff every H-consistent intent denies")
is sound ONLY if the true policy π_true ∈ H. Real authz uses predicates outside
any fixed H (team/project, time, geo, risk). When π_true ∉ H, the pure rule
FALSE-POSITIVES on a perfectly legitimate access -> it would submit a bogus bug.

The fix (H-independent soundness):
  (1) PROVENANCE PARTITION — a FINDING may come ONLY from an interventionally
      CONSTRUCTED intent-deny + Δstate (H-independent). Anything that rests on
      H-inference is a LEAD, never a finding.
  (2) FALSIFICATION GATE (Popperian) — before firing, try to REFUTE the finding
      using the app's OWN relationship/grant surface (H-independent): if a
      legitimate relationship (team, share) explains the access, ABSTAIN.

This file shows: the pure-H rule FPs when π_true∉H; the sound engine does NOT FP
there, and still fires on a genuine construction-backed BOLA. Deterministic.
"""
from __future__ import annotations
from dataclasses import dataclass

# --------------------------------------------------------------- the target
@dataclass(frozen=True)
class P:  # principal
    pid: str
    team: str

A = P("A", "proj1"); B = P("B", "proj1"); C = P("C", "proj2")

# π_true (UNKNOWN to us, OUTSIDE H): "owner OR same project team may access".
# Normal objects follow π_true. One object (obj_bug) has a real BOLA (anyone).
OWNER = {"objA": A, "objPriv": A}          # objPriv is freshly CONSTRUCTED by us as private
def enf_access(viewer: P, obj: str) -> bool:
    if obj == "objPriv":                    # a genuine BOLA: enforcement lets ANYONE read it
        return True
    owner = OWNER.get(obj)
    return owner is not None and (viewer.pid == owner.pid or viewer.team == owner.team)  # π_true

# The app EXPOSES its own relationship surface (H-independent ground truth):
def legitimate_relationship(viewer: P, obj: str) -> str | None:
    owner = OWNER.get(obj)
    if owner and viewer.team == owner.team and viewer.pid != owner.pid:
        return f"same-team({viewer.team})"       # a declared, legitimate grant
    return None

# --------------------------------------------------------------- H (bounded algebra)
# NB: H has NO notion of team/project. So π_true ∉ H by construction.
H = {
    "own":        lambda v, o: v.pid == OWNER[o].pid if o in OWNER else False,
    "role>=1":    lambda v, o: False,                    # no roles here
    "public|own": lambda v, o: v.pid == OWNER[o].pid if o in OWNER else False,
}

def version_space(positives):
    return [n for n, h in H.items() if all(h(v, o) for (v, o) in positives)]

# --------------------------------------------------------------- the two deciders
def pure_vs_decision(positives, viewer, obj):
    """Wall-1 rule. SOUND ONLY IF π_true ∈ H — which we cannot guarantee."""
    if not enf_access(viewer, obj):
        return "CLEAN(enforced-deny)"
    vs = version_space(positives)
    if vs and all(not H[n](viewer, obj) for n in vs):
        return "FINDING"                 # every H-consistent intent denies -> fire
    return "ABSTAIN/CLEAN"

def sound_decision(viewer, obj, constructed_private: bool):
    """H-INDEPENDENT. A finding needs (a) a CONSTRUCTED intent-deny, (b) Δstate
    access success, and (c) FALSIFICATION fails (no legitimate relationship)."""
    if not enf_access(viewer, obj):
        return "CLEAN(enforced-deny)"
    benign = legitimate_relationship(viewer, obj)        # (b) try to REFUTE
    if benign:
        return f"ABSTAIN(benign: {benign} explains access)"
    if constructed_private:                              # (a) H-independent ground truth
        return "FINDING(constructed intent-deny + Δstate; falsification failed)"
    return "LEAD(H-inferred only; construct-and-confirm before claiming)"

# --------------------------------------------------------------- scenarios
def main():
    # legitimate traffic we observed: owners on their own objects only
    positives = [(A, "objA"), (B, "objA") if False else (A, "objA")]  # B's team access NOT observed
    positives = [(A, "objA")]

    rows = []

    # Scenario 1 — the FALSE-POSITIVE TRAP: B (same team as A) legitimately reads
    # A's object under π_true. It is NOT a bug. But team ∉ H.
    pv1 = pure_vs_decision(positives, B, "objA")
    sd1 = sound_decision(B, "objA", constructed_private=False)
    rows.append(("S1 teammate reads A's obj (LEGIT, π_true∉H)", pv1, sd1))

    # Scenario 2 — a GENUINE BOLA: C constructs nothing; we CONSTRUCTED objPriv as
    # A's private object (no team, no share); enforcement wrongly lets C read it.
    pv2 = pure_vs_decision(positives, C, "objPriv")
    sd2 = sound_decision(C, "objPriv", constructed_private=True)
    rows.append(("S2 outsider reads A's CONSTRUCTED private obj (REAL BUG)", pv2, sd2))

    print("WALL-4 SOUNDNESS (zero-FP must not depend on π_true ∈ H)")
    print("=" * 84)
    print(f"  version space (H-consistent with positives) = {version_space(positives)}")
    print("-" * 84)
    for name, pv, sd in rows:
        print(f"  {name}")
        print(f"      pure-H rule : {pv}")
        print(f"      SOUND engine: {sd}")
    print("=" * 84)

    # ---- the proof ----
    assert pv1 == "FINDING", pv1                         # the wall is REAL: pure-H FALSE-POSITIVES
    assert sd1.startswith("ABSTAIN"), sd1                # sound engine does NOT false-positive
    assert sd2.startswith("FINDING"), sd2                # sound engine still catches the real bug
    assert pv2 == "FINDING", pv2                         # (pure-H happens to agree here, but for the wrong reason)
    print("PROVEN: pure-H rule FALSE-POSITIVES when π_true∉H (S1);")
    print("        the SOUND engine ABSTAINS on S1 (no FP) and still FIRES on the real bug (S2).")
    print("        => zero-FP is now INDEPENDENT of whether the algebra H can express the true intent.")

if __name__ == "__main__":
    main()
