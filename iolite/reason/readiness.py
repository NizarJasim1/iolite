"""
reason · readiness — the expected-value submission gate (GO / HOLD / DROP). Turns a
confirmed-or-candidate finding into a decision by combining ONLY observable factors:

    EV = P(valid) · P(in-scope) · P(non-informational) · P(original) · E[payout]

  * P(valid)          1.0 if ONYX-confirmed, else 0.4 (offline hypothesis)
  * P(in-scope)       1.0 in scope (Scope-Guard already filtered), else 0.1
  * P(non-informational) from the impact band (low bands are often informational)
  * P(original)       the collision proxy (never a claimed probability)
  * E[payout]         a deterministic per-band estimate

An UNCONFIRMED finding can never be GO (you cannot submit what ONYX has not proven) —
it is HOLD at best. Nothing here is a verdict on the vulnerability (ONYX owns that);
it is a decision about the OPERATOR'S TIME. Deterministic (QL4). Serves goal 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .collision import collision_score, CollisionScore

_PAYOUT_BY_BAND = {"critical": 2000.0, "high": 800.0, "medium": 300.0, "low": 50.0, "": 100.0}
_NONINFORM_BY_BAND = {"critical": 0.95, "high": 0.90, "medium": 0.75, "low": 0.35, "": 0.6}
_GO_EV = 150.0
_HOLD_EV = 40.0


@dataclass
class Readiness:
    cand_key: str
    verdict: str                        # GO | HOLD | DROP
    ev: float
    e_payout: float
    factors: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


def assess(cand, impact_band: str, collision: CollisionScore, confirmed: bool,
           in_scope: bool = True) -> Readiness:
    band = impact_band if impact_band in _PAYOUT_BY_BAND else ""
    p_valid = 1.0 if confirmed else 0.4
    p_scope = 1.0 if in_scope else 0.1
    p_noninform = _NONINFORM_BY_BAND[band]
    p_original = max(0.05, collision.p_original)
    e_payout = _PAYOUT_BY_BAND[band]
    ev = round(p_valid * p_scope * p_noninform * p_original * e_payout, 1)

    if not in_scope:
        verdict = "DROP"
    elif not confirmed:
        verdict = "HOLD" if ev >= _HOLD_EV else "DROP"     # never GO without ONYX
    elif ev >= _GO_EV:
        verdict = "GO"
    elif ev >= _HOLD_EV:
        verdict = "HOLD"
    else:
        verdict = "DROP"

    factors = {"p_valid": p_valid, "p_scope": p_scope, "p_noninformational": p_noninform,
               "p_original": p_original, "e_payout": e_payout}
    reasons = [
        f"P(valid)={p_valid} ({'ONYX-confirmed' if confirmed else 'offline hypothesis — cannot GO'})",
        f"P(scope)={p_scope}", f"P(non-informational)={p_noninform} (band={band or 'n/a'})",
        f"P(original)={p_original} (collision proxy)", f"E[payout]=${e_payout}",
        f"⇒ EV=${ev} → {verdict}",
    ]
    return Readiness(cand.cand_key, verdict, ev, e_payout, factors, reasons)


def assess_report(rep, confirmed_keys=None, kb_sig: dict | None = None,
                  in_scope: bool = True) -> list[Readiness]:
    """Assess every candidate in a ReasonReport, ranked by EV (desc). `confirmed_keys`
    is the set of ONYX-confirmed cand_keys (from a live CEGAR run); offline it is empty
    ⇒ every finding is HOLD/DROP (honest: nothing is GO until ONYX proves it)."""
    confirmed_keys = confirmed_keys or set()
    out: list[Readiness] = []
    for c in rep.candidates:
        band = rep.impact[c.cand_key].band if c.cand_key in rep.impact else ""
        nov = rep.novelty[c.cand_key].score if c.cand_key in rep.novelty else 5
        col = collision_score(c, nov, kb_sig)
        out.append(assess(c, band, col, confirmed=c.cand_key in confirmed_keys,
                          in_scope=in_scope))
    out.sort(key=lambda r: (-r.ev, r.cand_key))
    return out


def summary(readies: list[Readiness]) -> dict:
    d = {"GO": 0, "HOLD": 0, "DROP": 0}
    for r in readies:
        d[r.verdict] = d.get(r.verdict, 0) + 1
    return d
