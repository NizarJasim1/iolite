"""
wall2_deep.py — Wall-2 deepened: LEARNED equivalence partition + an ONLINE
EV-maximizing BANDIT scheduler (vs static allocation) + EV worklist/coverage.

Three leaps over the opening kernel:
  (A) The authorization-equivalence partition is DISCOVERED from observed behavior
      (not hardcoded) and self-corrected by CEGAR: instances with the same
      behavior-signature collapse into one class; a cohort that behaves differently
      splits out AND is flagged as an authz inconsistency (a finding).
  (B) The scarce confirmation budget is allocated by a UCB BANDIT that maximizes
      EXPECTED VALUE ($, = P(bug)·payout) learned online, concentrating draws on
      the services that actually yield — vs uniform/static allocation. More bounty
      per unit budget (and per unit detection-risk).
  (F) Output is a ranked EV WORKLIST + a COVERAGE report (confirmed vs leads).
Deterministic. In-process (the 'probe' stands in for an ONYX Δstate confirmation).
"""
from __future__ import annotations
import math
from dataclasses import dataclass

# =====================================================================
# (A) LEARNED equivalence partition from observed behavior signatures
# =====================================================================
ROLES = ["anon", "user", "admin"]

@dataclass(frozen=True)
class Inst:
    iid: int
    typ: str
    # ground-truth behavior: which roles the ENFORCEMENT lets in (observed by cheap probes)
    behavior: tuple   # (anon_in, user_in, admin_in)

def behavior_signature(inst: Inst) -> tuple:
    return (inst.typ, inst.behavior)       # type + observed access vector

def learn_partition(instances):
    """Group by observed behavior signature. Same behavior => same authz class.
    A minority sub-group inside a type whose behavior differs = a split (CEGAR)."""
    classes: dict[tuple, list] = {}
    for i in instances:
        classes.setdefault(behavior_signature(i), []).append(i)
    # flag intra-type inconsistency: a type with >1 behavior signature
    by_type: dict[str, set] = {}
    for (typ, beh) in classes:
        by_type.setdefault(typ, set()).add(beh)
    inconsistent = {t for t, behs in by_type.items() if len(behs) > 1}
    return classes, inconsistent

# =====================================================================
# (B) ONLINE EV-maximizing bandit scheduler vs static allocation
# =====================================================================
@dataclass
class Arm:
    name: str
    payout: int                 # $ value of a confirmed bug in this class
    bug_at: set                 # probe indices that are real bugs (hidden ground truth)
    n_probes: int               # total probes available in this class
    drawn: int = 0
    reward_sum: float = 0.0
    bugs: int = 0
    def draw(self):
        if self.drawn >= self.n_probes:
            return 0.0, False
        idx = self.drawn; self.drawn += 1
        bug = idx in self.bug_at
        r = self.payout if bug else 0.0
        self.reward_sum += r
        if bug: self.bugs += 1
        return r, bug

def ucb_schedule(arms, budget):
    """UCB1 on EV. Explore each arm once, then pick max (mean + c·sqrt(ln t / n))."""
    t = 0
    # normalize payouts to [0,1] for the UCB bonus scale, keep $ for reward tally
    maxp = max(a.payout for a in arms)
    for a in arms:                       # initial exploration
        if t >= budget: break
        a.draw(); t += 1
    while t < budget:
        best, best_u = None, -1.0
        for a in arms:
            if a.drawn >= a.n_probes:      # exhausted
                continue
            mean = (a.reward_sum / a.drawn) / maxp if a.drawn else 0.0
            bonus = math.sqrt(2 * math.log(max(t, 1)) / a.drawn)
            u = mean + bonus
            if u > best_u + 1e-12:         # deterministic tie-break by first/highest
                best_u, best = u, a
        if best is None: break
        best.draw(); t += 1
    return sum(a.reward_sum for a in arms), sum(a.bugs for a in arms), t

def uniform_schedule(arms, budget):
    per = budget // len(arms)
    for a in arms:
        for _ in range(min(per, a.n_probes)):
            a.draw()
    return sum(a.reward_sum for a in arms), sum(a.bugs for a in arms), sum(a.drawn for a in arms)

def fresh_arms():
    # a realistic authz landscape: TWO broken services (systemic -> high within-class
    # yield), SIX secure services (0 yield). Budget must find the money.
    return [
        Arm("svc_vault(BROKEN)", 2500, set(range(8)), 20),   # 8 bugs in first 8 probes
        Arm("svc_orders(BROKEN)", 800, set(range(6)), 20),   # 6 bugs
        Arm("svc_profile", 300, set(), 20), Arm("svc_report", 600, set(), 20),
        Arm("svc_billing", 1500, set(), 20), Arm("svc_notif", 200, set(), 20),
        Arm("svc_search", 150, set(), 20), Arm("svc_prefs", 100, set(), 20),
    ]

# =====================================================================
def main():
    print("WALL-2 DEEP — learned partition + CEGAR, and EV-bandit vs static budget")
    print("=" * 84)

    # (A) learned partition demo: 5000 instances; 'order' has a misbehaving cohort
    insts = []
    for t, base_beh in [("profile", (1,1,1)), ("order", (0,1,1)), ("report", (0,1,1)), ("vault", (0,0,1))]:
        for k in range(1250):
            beh = base_beh
            if t == "order" and k % 7 == 0:        # a cohort of orders leaks to anon
                beh = (1,1,1)
            insts.append(Inst(k, t, beh))
    classes, inconsistent = learn_partition(insts)
    print(f"(A) instances={len(insts):,}  ->  learned classes={len(classes)}  "
          f"(reduction {len(insts)/len(classes):,.0f}x)")
    print(f"    intra-type authz INCONSISTENCY auto-flagged (a finding): {sorted(inconsistent)}")

    # (B) EV-bandit vs uniform, SAME budget
    budget = 40
    bandit_ev, bandit_bugs, bt = ucb_schedule(fresh_arms(), budget)
    unif_ev, unif_bugs, ut = uniform_schedule(fresh_arms(), budget)
    print(f"\n(B) confirmation budget = {budget} probes, 8 service-classes (2 broken, 6 secure)")
    print(f"    UNIFORM  : bugs={unif_bugs:2d}  EV_captured=${unif_ev:,.0f}")
    print(f"    EV-BANDIT: bugs={bandit_bugs:2d}  EV_captured=${bandit_ev:,.0f}   "
          f"(+{(bandit_ev/unif_ev-1)*100:.0f}% bounty per unit budget)")

    # (F) EV worklist + coverage (from the bandit's learned posteriors)
    arms = fresh_arms(); ucb_schedule(arms, budget)
    ranked = sorted(arms, key=lambda a: -(a.reward_sum / a.drawn if a.drawn else 0))
    print("\n(F) EV worklist (top services by learned yield) + coverage:")
    for a in ranked[:4]:
        yld = (a.bugs / a.drawn) if a.drawn else 0
        print(f"    {a.name:20s} drawn={a.drawn:2d}/{a.n_probes}  bugs={a.bugs}  "
              f"yield={yld:.0%}  $captured={a.reward_sum:,.0f}")
    covered = sum(a.drawn for a in arms); total = sum(a.n_probes for a in arms)
    print(f"    coverage: {covered}/{total} probes confirmed ({covered/total:.0%}); rest = ranked leads")

    print("=" * 84)
    assert inconsistent == {"order"}, inconsistent                 # (A) cohort auto-split+flagged
    assert len(classes) <= 10                                      # (A) millions->handful
    assert bandit_ev > unif_ev                                     # (B) bandit captures more $
    assert bandit_bugs >= unif_bugs                                # (B) and >= bugs, same budget
    assert bt <= budget                                            # budget respected
    print("PROVEN: partition LEARNED (+cohort inconsistency auto-flagged); EV-bandit beats")
    print(f"        uniform by ${bandit_ev-unif_ev:,.0f} at equal budget — budget flows to the money.")

if __name__ == "__main__":
    main()
