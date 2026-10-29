"""
wall1_construction.py — breaking Wall 1 (the deny-signal / recall wall) at the root.

ROOT CAUSE (framed): the version-space rule is SOUND but can only FIRE when the
hypothesis set is bounded from ABOVE (every consistent intent denies x). Bounding
from above needs NEGATIVE evidence (intent-deny). Passive observation of a well-
behaved client yields almost only POSITIVE examples -> the permissive hypothesis
("all") stays consistent -> the rule ABSTAINS -> recall collapses on exactly the
hardened targets we care about. (Positive-only identification is fundamentally
limited; you cannot pin a concept's upper boundary from positive data alone.)

THE BREAK (interventional, not observational): we OWN the principals, and the app
exposes authorization AFFORDANCES (a "make private" feature, share, revoke). Using
a privacy affordance as principal A is the DEVELOPER'S OWN DECLARATION that the
object is intent-denied to outsiders -- a ground-truth negative we MANUFACTURE on
demand, on ANY target, soundly. This climbs from "seeing" (confounded, Wall 1) to
"doing" (identifiable). We only manufacture a negative we can establish by
construction (cross-org isolation, or a per-user-private affordance); where we
cannot, we ABSTAIN -> zero false positives preserved.

This file PROVES: (1) the wall is real under passive data; (2) interventional
construction makes the SOUND rule fire on an opaque target that leaked no 403;
(3) where construction cannot establish deny (plausible team-visibility), it
still ABSTAINS -> no false positive.
"""
from __future__ import annotations
from dataclasses import dataclass

# --- hypothesis algebra over (caller_tenant, owner_tenant, caller==owner) ------
# Each hypothesis is a candidate INTENT. Novelty of the decision comes from WHICH
# survive the evidence, never from guessing at decision time.
H = {
    "own":   lambda cal, own, same_t: cal == own,                 # only the owner
    "team":  lambda cal, own, same_t: same_t,                     # same tenant/org may read
    "all":   lambda cal, own, same_t: True,                       # everyone (no privacy)
}

@dataclass(frozen=True)
class Access:
    caller: str      # principal id
    owner: str       # object owner id
    same_tenant: bool

def consistent(ev_pos, ev_neg):
    """Hypotheses consistent with positive (intended-allow) and negative
    (intended-deny) evidence. ev_* are lists of Access."""
    out = []
    for name, h in H.items():
        if all(h(a.caller, a.owner, a.same_tenant) for a in ev_pos) and \
           all(not h(a.caller, a.owner, a.same_tenant) for a in ev_neg):
            out.append(name)
    return out

def decide(ev_pos, ev_neg, x: Access, enforced_permit: bool) -> str:
    if not enforced_permit:
        return "CLEAN(enforced-deny)"
    vs = consistent(ev_pos, ev_neg)
    if not vs:
        return "ABSTAIN(intent-unreconstructable)"
    permit = [n for n in vs if H[n](x.caller, x.owner, x.same_tenant)]
    deny   = [n for n in vs if not H[n](x.caller, x.owner, x.same_tenant)]
    if permit == []:
        return "FINDING(all-consistent-intents-deny)"
    if deny == []:
        return "CLEAN(all-consistent-intents-permit)"
    return "ABSTAIN(ambiguous:%s)" % ",".join(vs)

# ----------------------------------------------------------------------------
# An OPAQUE hardened target: cross-tenant read of a "private" object SUCCEEDS
# (the latent bug), ids are opaque UUIDs, and it emits NO 403 in passive traffic.
# ----------------------------------------------------------------------------
def enforced_permit_crossorg_read() -> bool:
    return True   # the server WRONGLY lets B (org2) read A's (org1) private object

def main():
    report = []

    # Shared positive evidence: each owner reads their OWN object (legit traffic).
    # A in org1, B in org2. same_tenant=True only when caller & owner share org.
    pos = [Access("A", "A", True), Access("B", "B", True)]

    # The access under test: B (org2) reads A's (org1) private object.
    x = Access("B", "A", same_tenant=False)

    # --- (1) PASSIVE: positive-only. The wall. ------------------------------
    v1 = decide(pos, [], x, enforced_permit_crossorg_read())
    report.append(("(1) passive / positive-only", v1, consistent(pos, [])))
    assert v1.startswith("ABSTAIN"), v1          # recall-killing abstention = the wall

    # --- (2) INTERVENTIONAL: manufacture a SOUND negative by construction. ---
    # do(create_private_object as A in org1) + B is an UNRELATED org we also own,
    # and we issued NO share. => "B(org2) must not read A(org1)'s private object"
    # is established BY CONSTRUCTION (the app's 'private' affordance = declared
    # intent), not harvested. This is a ground-truth negative on an opaque target.
    manufactured_neg = [Access("B", "A", same_tenant=False)]
    v2 = decide(pos, manufactured_neg, x, enforced_permit_crossorg_read())
    report.append(("(2) interventional / cross-org construct", v2, consistent(pos, manufactured_neg)))
    assert v2.startswith("FINDING"), v2          # the wall is broken: it FIRES, soundly

    # --- (3) SOUNDNESS GUARD: same-tenant, team-visibility is PLAUSIBLE. ------
    # Here we must NOT manufacture a negative (cannot establish deny by
    # construction), so the rule stays honest and ABSTAINS -> no false positive.
    y = Access("B2", "A", same_tenant=True)      # B2 and A share the org
    pos_same = [Access("A", "A", True), Access("B2", "B2", True)]
    v3 = decide(pos_same, [], y, enforced_permit=True)
    report.append(("(3) same-tenant / cannot construct deny", v3, consistent(pos_same, [])))
    assert v3.startswith("ABSTAIN"), v3          # zero-FP preserved under ambiguity

    print("WALL-1 BREAK: interventional intent identification")
    print("-" * 70)
    for name, v, vs in report:
        tag = "FIND " if v.startswith("FINDING") else ("ABST " if v.startswith("ABSTAIN") else "CLEAN")
        print(f"  [{tag}] {name:42s} -> {v}")
        print(f"          version-space = {vs}")
    print("-" * 70)
    print("passive abstains (wall real) ; construction fires (wall broken) ;")
    print("ambiguity still abstains (zero-FP preserved). all assertions passed.")

if __name__ == "__main__":
    main()
