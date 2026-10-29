"""
⑥ Authz-risk triage — deterministic, transparent, budgeted.

Mirrors ONYX's `triage.py` philosophy: on a giant surface the confirmation budget
must be spent on the highest-authorization-risk endpoints first. The score is an
auditable integer with named reasons — NO ML (QL4). Triage decides ORDER; ONYX's
Δstate confirmer decides TRUTH, so a high rank never fabricates a finding.

Signals (each adds a fixed, explainable weight):
  * object-addressed GET (IDOR/BOLA surface)          +10
  * enumerable id (sequential/numeric worst-case)     +ENUM_WEIGHT
  * privilege / admin / internal hint (BFLA)          +8
  * mutating verb on an addressed object              +5
  * value/authority effect (PAYMENT/PRICE/GRANT)      +6
  * ghost endpoint (archived-only; authz may have rotted) +7
  * sensitive noun in path                            +2 (capped)
  * cross-surface / field-projection                 +4
  * observed live (T1) — real ids available to thread +3
"""

from __future__ import annotations

from .models import Effect, Endpoint, SurfaceModel
from .idformat import enumerability_of
from .models import EvidenceTier

_SENSITIVE = ("user", "account", "order", "invoice", "payment", "card", "document",
              "file", "message", "profile", "member", "project", "group", "ticket",
              "token", "secret", "key", "admin", "billing", "subscription", "report")


def score_endpoint(ep: Endpoint, model: SurfaceModel | None = None) -> None:
    """Fill ep.risk / ep.risk_reasons in place. Deterministic."""
    score = 0
    reasons: list[str] = []
    m = ep.method.upper()
    path = ep.path
    has_id = "{id}" in path

    if m == "GET" and (ep.effect == Effect.OBJECT_ACCESS or has_id):
        score += 10
        reasons.append("+10 object-addressed GET (BOLA surface)")
    level, note, w = enumerability_of(ep.observed_ids)
    if w:
        score += w
        reasons.append(f"+{w} enumerable id ({level})")
    if any(("admin" in r or "role" in r or "internal" in r or "staff" in r or "hint:" in r)
           for r in ep.role_hints):
        score += 8
        reasons.append("+8 privilege/admin hint (BFLA)")
    if m in ("PUT", "PATCH", "DELETE") and has_id:
        score += 5
        reasons.append("+5 mutating verb on addressed object")
    if ep.effect in (Effect.PAYMENT, Effect.PRICE, Effect.AUTHORITY_GRANT, Effect.AUTHORITY):
        score += 6
        reasons.append(f"+6 value/authority effect ({ep.effect.value})")
    if "ghost:removed-from-current-ui" in ep.role_hints:
        score += 7
        reasons.append("+7 ghost endpoint (archived-only — authz may have rotted)")
    if ep.effect in (Effect.CROSS_SURFACE, Effect.FIELD_PROJECTION):
        score += 4
        reasons.append(f"+4 {ep.effect.value.lower()} surface")
    sens = sorted({kw for kw in _SENSITIVE if kw in path.lower()})
    if sens:
        add = min(2 * len(sens), 6)
        score += add
        reasons.append(f"+{add} sensitive noun ({','.join(sens[:3])})")
    if ep.best_tier == EvidenceTier.T1_LIVE:
        score += 3
        reasons.append("+3 observed live (real ids available to thread)")

    ep.risk = score
    ep.risk_reasons = reasons


def rank(model: SurfaceModel) -> list[Endpoint]:
    for ep in model.endpoints.values():
        score_endpoint(ep, model)
    return model.sorted_endpoints()


def budgeted(model: SurfaceModel, budget: int) -> list[Endpoint]:
    """Top-`budget` endpoints by risk — where a fixed confirmation budget goes first."""
    return rank(model)[:max(0, budget)]
