"""
⑧ ONYX bridge — emit an ONYX/AuthPath-compatible spec.json.

v0.6: tier-aware, probeability-aware emission (QL5 honesty).

The `contract` now contains ONLY endpoints the plan can actually exercise (a
concrete request ONYX will issue). Every other surfaced endpoint is demoted to a
`_iolite.leads` entry with WHY it is a lead and WHAT acquisition would activate it.
IOLITE never hands ONYX a contract entry it cannot probe, and never inflates the
coverage number. Each contract entry carries its evidence tier + confidence in a
parallel `_iolite.contract_meta` map (values stay `{"effect": ...}` for ONYX).

Emitted schema (ONYX ignores unknown keys, so it runs as-is):
  { base_url, scope, principals[], contract{}, seed[], probe[], _engagement, _iolite }
Determinism (QL4): keys sorted, ordering stable. Secrets redacted to $TOKEN_<pid>.
"""

from __future__ import annotations

import json

from .models import Effect, EvidenceTier, SurfaceModel
from .normalize import endpoint_key
from .replay import ReplayPlan
from .roe import Engagement
from .scope_guard import ScopeConfig


def plan_keys(plan: ReplayPlan) -> set[str]:
    """The endpoint keys the plan actually touches (seed + probe)."""
    keys = set()
    for item in list(plan.seed) + list(plan.probe):
        keys.add(endpoint_key(item.get("method", "GET"), item.get("path", "/")))
    return keys


def _confidence(tier: EvidenceTier) -> str:
    return {EvidenceTier.T1_LIVE: "high",
            EvidenceTier.T2_CAPTURED: "medium",
            EvidenceTier.T3_ARCHIVED: "low",
            EvidenceTier.T4_INFERRED: "low"}.get(tier, "low")


def build_contract(model: SurfaceModel, keys: set[str]) -> dict:
    """endpoint_key -> {effect}. ONLY probeable endpoints (in the plan) with a real
    effect. Values kept as {"effect": ...} for ONYX; meta rides in contract_meta."""
    out = {}
    for ep in model.sorted_endpoints():
        if ep.effect != Effect.NONE and ep.key in keys:
            out[ep.key] = {"effect": ep.effect.value}
    return dict(sorted(out.items()))


def build_contract_meta(model: SurfaceModel, keys: set[str]) -> dict:
    out = {}
    for ep in model.sorted_endpoints():
        if ep.effect != Effect.NONE and ep.key in keys:
            out[ep.key] = {"tier": ep.best_tier.value,
                           "confidence": _confidence(ep.best_tier),
                           "risk": ep.risk}
    return dict(sorted(out.items()))


def build_leads(model: SurfaceModel, keys: set[str]) -> list[dict]:
    """Surfaced endpoints IOLITE cannot yet probe — demoted to leads with an
    activation hint (what to capture to make them testable). Never in the contract."""
    leads = []
    for ep in model.sorted_endpoints():
        if ep.effect == Effect.NONE or ep.key in keys:
            continue
        if ep.key in model.ghost_keys:
            reason = "archived-only ghost — removed from current UI, may still be live"
            activation = "request it once as one of your accounts to confirm it is live, then re-run"
        else:
            reason = "declared/mined, but no concrete id observed and no controlled principal reached it"
            activation = "capture an authenticated request to this endpoint with one of your accounts, then re-run"
        leads.append({"endpoint": ep.key, "effect": ep.effect.value,
                      "tier": ep.best_tier.value, "confidence": _confidence(ep.best_tier),
                      "risk": ep.risk, "reason": reason, "activation": activation})
    return leads


def build_spec(model: SurfaceModel, plan: ReplayPlan, scope: ScopeConfig,
               engagement: Engagement | None = None, redact: bool = True) -> dict:
    base_url = model.base_url or (f"https://{model.host}" if model.host else "")
    principals = [p.to_spec(redact=redact) for p in
                  sorted(model.principals, key=lambda x: x.pid)]
    resolved = sorted(model.hosts_seen) or ([model.host] if model.host else None)

    keys = plan_keys(plan)
    contract = build_contract(model, keys)
    leads = build_leads(model, keys)

    spec = {
        "base_url": base_url,
        "scope": scope.to_spec(resolved_hosts=resolved),
        "principals": principals,
        "contract": contract,
        "seed": plan.seed,
        "probe": plan.probe,
        "_iolite": {
            "tool": "IOLITE",
            "version": __import__("iolite").__version__,
            "endpoints_total": len(model.endpoints),
            "contract_probeable": len(contract),
            "leads": leads,
            "contract_meta": build_contract_meta(model, keys),
            "ghost_endpoints": sorted(model.ghost_keys),
            "probe_families": {"horizontal": plan.horizontal, "vertical": plan.vertical},
            "note": "contract = endpoints the plan can actually exercise; everything "
                    "else is a lead needing acquisition. Every finding is still decided "
                    "by ONYX Δstate confirmation (QL5).",
        },
    }
    if engagement is not None:
        spec["_engagement"] = engagement.as_manifest()
    ranked = model.sorted_endpoints()[:20]
    spec["_iolite"]["top_candidates"] = [
        {"endpoint": ep.key, "risk": ep.risk, "effect": ep.effect.value,
         "probeable": ep.key in keys, "reasons": ep.risk_reasons}
        for ep in ranked if ep.risk > 0
    ]
    return spec


def write_spec(spec: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(spec, fh, indent=2, sort_keys=False)
        fh.write("\n")
