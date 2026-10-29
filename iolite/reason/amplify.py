"""
reason · amplify — impact/severity amplifier. A confirmed authz gap is Medium until
impact is shown; this turns each candidate into a ranked severity + a Critical
narrative (effect × sensitivity × scale × direction × chain × tenant), and offers a
BOUNDED scale-proof probe set to demonstrate blast radius.

Deterministic, transparent (an integer with named reasons, like triage). This scores
LIKELY impact to prioritise — it never asserts a finding (ONYX decides that, QL5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Effect, SurfaceModel
from ..idformat import classify
from .differ import ReasonCandidate

# effect → base weight (funds/authority highest)
_EFFECT_W = {
    Effect.AUTHORITY_GRANT.value: 10, Effect.PAYMENT.value: 10, Effect.AUTHORITY.value: 9,
    Effect.PRICE.value: 8, Effect.OWNERSHIP.value: 8, Effect.INVENTORY.value: 6,
    Effect.COUPON.value: 6, Effect.STATE_GATE.value: 6, Effect.CROSS_SURFACE.value: 6,
    Effect.OBJECT_ACCESS.value: 5, Effect.FIELD_PROJECTION.value: 5, Effect.NONE.value: 1,
}
_SENS_HIGH = ("payment", "card", "ssn", "kyc", "wallet", "bank", "invoice", "account",
              "transfer", "balance", "credential", "password", "token", "admin",
              "internal", "export", "ssn", "passport")
_SENS_MED = ("user", "order", "profile", "document", "message", "email", "phone",
             "address", "ticket", "booking", "trip", "report", "file")
_TENANT = ("tenant", "org", "organization", "company", "workspace", "team", "account_id")
_VERTICAL_FAMILIES = ("intent_bfla", "chain_privilege_lateral", "assumption_internal",
                      "assumption_client_role")

_BANDS = [(16, "critical"), (11, "high"), (6, "medium"), (0, "low")]


@dataclass
class ImpactScore:
    cand_key: str
    score: int
    band: str
    reasons: list[str] = field(default_factory=list)
    narrative: str = ""


def _band(score: int) -> str:
    for thresh, name in _BANDS:
        if score >= thresh:
            return name
    return "low"


def score_candidate(c: ReasonCandidate, model: SurfaceModel) -> ImpactScore:
    reasons: list[str] = []
    s = _EFFECT_W.get(c.onyx_effect, 3)
    reasons.append(f"+{s} effect {c.onyx_effect}")

    hay = (c.path + " " + c.endpoint_key).lower()
    if any(w in hay for w in _SENS_HIGH):
        s += 4; reasons.append("+4 sensitive surface (funds/PII/authority)")
    elif any(w in hay for w in _SENS_MED):
        s += 2; reasons.append("+2 user-data surface")

    if c.object_id:
        kind, _why = classify(str(c.object_id))
        if kind in ("sequential", "numeric"):
            s += 3; reasons.append("+3 enumerable id → blast radius = whole collection")

    if c.family in _VERTICAL_FAMILIES or c.intent_class == "ADMIN_ONLY":
        s += 2; reasons.append("+2 vertical / privilege (BFLA)")

    if c.depth >= 2 or c.chain_from:
        s += 3; reasons.append("+3 part of a confirmed chain (composition → Critical)")

    if any(w in hay for w in _TENANT):
        s += 3; reasons.append("+3 tenant/org boundary (isolation break)")

    band = _band(s)
    narrative = _narrative(c, band, reasons)
    return ImpactScore(cand_key=c.cand_key, score=s, band=band,
                       reasons=reasons, narrative=narrative)


def _narrative(c: ReasonCandidate, band: str, reasons: list[str]) -> str:
    bits = []
    if any("funds/PII" in r for r in reasons):
        bits.append("sensitive (funds/PII/authority) data")
    if any("enumerable" in r for r in reasons):
        bits.append("enumerable at scale (whole collection)")
    if any("vertical" in r for r in reasons):
        bits.append("privilege escalation")
    if any("chain" in r for r in reasons):
        bits.append("multi-step chain")
    if any("tenant" in r for r in reasons):
        bits.append("cross-tenant")
    body = ", ".join(bits) if bits else "single-object access"
    return (f"If ONYX confirms: {c.onyx_effect} — {body}. Likely severity **{band.upper()}**. "
            f"Impact to demonstrate for the report: {body}.")


def amplify(cands: list[ReasonCandidate], model: SurfaceModel) -> dict[str, ImpactScore]:
    return {c.cand_key: score_candidate(c, model) for c in cands}


def ranked(cands: list[ReasonCandidate], model: SurfaceModel) -> list[tuple[ReasonCandidate, ImpactScore]]:
    scored = [(c, score_candidate(c, model)) for c in cands]
    scored.sort(key=lambda t: (-t[1].score, t[0].cand_key))
    return scored


def scale_probes(c: ReasonCandidate, n: int = 3) -> list[ReasonCandidate]:
    """BOUNDED blast-radius proof: a few more adjacent ids for an enumerable confirmed
    read (reads only, own principal). Demonstrates scale for the report — never mass
    enumeration."""
    out: list[ReasonCandidate] = []
    if not c.object_id:
        return out
    try:
        base = int(str(c.object_id))
    except ValueError:
        return out
    kind, _ = classify(str(c.object_id))
    if kind not in ("sequential", "numeric"):
        return out
    for d in range(2, 2 + max(0, n)):
        nid = str(base + d)
        npath = c.path.replace(str(c.object_id), nid, 1)
        if npath == c.path:
            break
        out.append(ReasonCandidate(
            endpoint_key=c.endpoint_key, method=c.method, path=npath,
            gap_kind="amplify_scale", intent_class=c.intent_class,
            intent_confidence="medium", onyx_effect=c.onyx_effect,
            probe_pids=list(c.probe_pids), holder_pid=c.holder_pid, object_id=nid,
            carrier=c.carrier, family="amplify_scale", depth=c.depth,
            chain_from=c.cand_key,
            rationale=f"scale-proof: adjacent id {nid} to demonstrate blast radius (bounded)"))
    return out
