"""
wall4_causal.py — Wall-4 qualitative leap: CAUSAL falsification + triage dossier.

Flaw in the first Wall-4 gate (correlational): "a relationship exists -> benign ->
abstain". That FALSE-NEGATIVES on a real BOLA when the attacker merely HAPPENS to
have an unrelated relationship (e.g. same team) that is NOT what granted the access.

Leap (causal / interventional): don't ask "does a relationship exist?" ask "is the
relationship the CAUSE?" — with a NO-RELATIONSHIP CONTROL principal D we own:
  * D (no relationship) also gets in  -> relationship is NOT the cause -> REAL BOLA (fire)
  * only the related principal gets in -> relationship IS the cause      -> benign (abstain)
This recovers recall lost to over-abstention WITHOUT introducing false positives,
and keeps zero-FP H-independent (decision rests on construction + Δstate + the
control differential, never on the hypothesis algebra).

Plus bug-bounty features: evidence provenance TIERS (only T2+ is submittable) and
an auto-generated TRIAGE DOSSIER (refuted benign explanations + PoC). Deterministic.
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass(frozen=True)
class P:
    pid: str
    team: str

A  = P("A", "proj1")     # owner
B  = P("B", "proj1")     # same team as A -> HAS a (true) relationship to A
C  = P("C", "proj2")     # outsider, no relationship
D  = P("D", "ctl")       # dedicated NO-RELATIONSHIP control principal we own (pooled, reused)

# object kinds (we CONSTRUCT a private instance of each as A):
#   secure_team : owner OR same-team may access      (legitimate design)
#   bug_universal: anyone may access                  (a real BOLA)
def enf(viewer: P, kind: str) -> bool:
    if kind == "bug_universal": return True                     # BOLA: universal
    if kind == "secure_team":   return viewer.pid == "A" or viewer.team == "proj1"
    return False

def value_reproduced(viewer: P, kind: str) -> bool:
    # a granted read reproduces A's constructed private marker (Δstate witness)
    return enf(viewer, kind)

def relationship(viewer: P) -> str | None:
    return f"same-team({viewer.team})" if viewer.team == "proj1" and viewer.pid != "A" else None

# --------------------------------------------------------------- deciders
def decide_naive(viewer, kind):
    """First Wall-4 gate: correlational falsification."""
    if not enf(viewer, kind): return "CLEAN"
    if relationship(viewer):  return "ABSTAIN"       # relationship exists -> assume benign
    return "FINDING"

@dataclass
class Verdict:
    verdict: str; tier: str; why: str
    refuted: list = field(default_factory=list)

def decide_causal(viewer, kind, constructed=True) -> Verdict:
    """H-independent: construction + Δstate + CAUSAL falsification via control D."""
    if not enf(viewer, kind):
        return Verdict("CLEAN", "T-", "enforced-deny")
    if not value_reproduced(viewer, kind):
        return Verdict("ABSTAIN", "T0", "200 but no Δstate value reproduced")
    refuted = []
    rel = relationship(viewer)
    # CAUSAL test: does the no-relationship control also get in?
    control_in = enf(D, kind) and value_reproduced(D, kind)
    if rel and not control_in:
        # removing the relationship removes the access -> relationship IS the cause
        return Verdict("ABSTAIN", "T1",
                       f"benign: '{rel}' is the CAUSE (no-relationship control D is denied)")
    if rel and control_in:
        refuted.append(f"'{rel}' exists but is NOT the cause (control D with no relationship also got in)")
    if not rel:
        refuted.append("attacker has no relationship to the object")
    if not constructed:
        return Verdict("LEAD", "T1", "inferred only; construct-and-confirm before claiming", refuted)
    return Verdict("FINDING", "T2",
                   "constructed intent-deny + Δstate + causal falsification failed", refuted)

def dossier(viewer, kind, v: Verdict) -> str:
    return "\n".join([
        "  ── TRIAGE DOSSIER ──────────────────────────────────────────",
        f"   class        : BOLA (OWASP API1:2023) on kind '{kind}'",
        f"   provenance    : {v.tier}  (submittable iff T2+)",
        f"   construction  : A created a PRIVATE instance; attacker {viewer.pid} is not the owner",
        f"   Δstate        : {viewer.pid} reproduced A's private marker (before→after read-back)",
        f"   causal control: no-relationship principal D also obtained access "
        f"({'YES → relationship not the cause' if enf(D,kind) else 'no'})",
        "   benign refuted: " + ("; ".join(v.refuted) if v.refuted else "none"),
        f"   PoC           : as {viewer.pid}: GET /obj/<A-private-id>  → returns A's private data",
        "  ────────────────────────────────────────────────────────────",
    ])

def main():
    cases = [
        ("S1 B(team) vs secure_team  [LEGIT]",      B, "secure_team"),
        ("S2 B(team) vs bug_universal [REAL BOLA]",  B, "bug_universal"),  # the FN trap
        ("S3 C(outsider) vs bug_universal [REAL]",   C, "bug_universal"),
        ("S4 C(outsider) vs secure_team [SECURE]",   C, "secure_team"),
    ]
    print("WALL-4 CAUSAL FALSIFICATION (naive gate vs causal gate)")
    print("=" * 76)
    results = {}
    for name, v, kind in cases:
        naive = decide_naive(v, kind)
        caus = decide_causal(v, kind)
        results[name] = (naive, caus.verdict, caus.tier)
        print(f"  {name}")
        print(f"      naive gate : {naive}")
        print(f"      CAUSAL gate: {caus.verdict} [{caus.tier}] — {caus.why}")
    print("-" * 76)
    # the headline: S2 is a real BOLA where attacker has an unrelated relationship
    print("  S2 is the leap: attacker B HAS a team relationship, but the bug is universal.")
    print(dossier(B, "bug_universal", decide_causal(B, "bug_universal")))
    print("=" * 76)
    # proof
    assert results["S2 B(team) vs bug_universal [REAL BOLA]"][0] == "ABSTAIN", "naive should FN here"
    assert results["S2 B(team) vs bug_universal [REAL BOLA]"][1] == "FINDING", "causal must catch it"
    assert results["S1 B(team) vs secure_team  [LEGIT]"][1] == "ABSTAIN", "causal must not FP on legit"
    assert results["S3 C(outsider) vs bug_universal [REAL]"][1] == "FINDING"
    assert results["S4 C(outsider) vs secure_team [SECURE]"][1] == "CLEAN"
    print("PROVEN: naive gate FALSE-NEGATIVES on S2 (misses a real BOLA); the CAUSAL")
    print("        gate catches S2 and S3, abstains on legit S1, clean on S4 — recall")
    print("        recovered, zero FP, and only T2 findings are marked submittable.")

if __name__ == "__main__":
    main()
