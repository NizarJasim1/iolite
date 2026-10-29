"""
Deterministic human surface dossier (Markdown).

Report-only: it summarises what IOLITE acquired and how it ranked it. It states no
verdicts (QL5) — every candidate is explicitly "for ONYX to confirm by Δstate".
"""

from __future__ import annotations

from .models import SurfaceModel
from .replay import ReplayPlan
from .temporal_diff import GhostReport
from .roe import Engagement
from . import surface_model
from .onyx_spec import plan_keys, build_leads


def render(model: SurfaceModel, plan: ReplayPlan, ghost: GhostReport,
           engagement: Engagement, flags: list[str]) -> str:
    st = surface_model.stats(model)
    L: list[str] = []
    L.append("# IOLITE — Surface Dossier")
    L.append("")
    L.append(f"**Target:** `{model.base_url or model.host or '(unset)'}`  ·  "
             f"**Program:** {engagement.program or '(unset)'}  ·  "
             f"**Attested:** {'yes' if engagement.attested() else 'NO — placeholder ROE'}")
    L.append("")
    L.append("> IOLITE acquires and ranks surface. Every candidate below is decided by "
             "ONYX Δstate confirmation — this dossier asserts no findings.")
    L.append("")

    L.append("## Surface at a glance")
    L.append("")
    L.append(f"- Endpoints: **{st['endpoints']}**  ·  contract-eligible effects across "
             f"{sum(v for k, v in st['by_effect'].items() if k != 'NONE')}")
    L.append(f"- Principals (yours): **{st['principals']}**  ·  observed accesses: "
             f"**{st['observed_accesses']}**  ·  objects held: **{st['objects']}**")
    L.append(f"- Ghost endpoints (archived-only): **{st['ghost_endpoints']}**  ·  "
             f"role-guarded endpoints: **{st['role_guarded']}**")
    L.append(f"- By effect: {st['by_effect']}")
    L.append(f"- By evidence tier: {st['by_tier']}")
    L.append("")

    L.append("## Top authorization-risk candidates (ranked, deterministic)")
    L.append("")
    L.append("| # | risk | endpoint | effect | tier | why |")
    L.append("|---|-----:|----------|--------|------|-----|")
    for i, ep in enumerate(model.sorted_endpoints()[:25], 1):
        if ep.risk <= 0:
            continue
        why = "; ".join(r.split(" ", 1)[1] for r in ep.risk_reasons[:3])
        L.append(f"| {i} | {ep.risk} | `{ep.key}` | {ep.effect.value} | "
                 f"{ep.best_tier.value} | {why} |")
    L.append("")

    if ghost.ghosts:
        L.append("## Ghost endpoints (time axis — verify still live, authz may have rotted)")
        L.append("")
        for ep in ghost.ghosts[:20]:
            L.append(f"- `{ep.key}`  ({ep.effect.value})")
        L.append("")

    leads = build_leads(model, plan_keys(plan))
    if leads:
        L.append("## Leads — surfaced but not yet probeable (need acquisition)")
        L.append("")
        L.append("| risk | endpoint | effect | tier | activate by |")
        L.append("|-----:|----------|--------|------|-------------|")
        for ld in leads[:20]:
            L.append(f"| {ld['risk']} | `{ld['endpoint']}` | {ld['effect']} | "
                     f"{ld['tier']} | {ld['activation']} |")
        L.append("")

    roles = surface_model.role_matrix(model)
    if roles:
        L.append("## Privilege-guarded surface (BFLA axis)")
        L.append("")
        for r in roles[:20]:
            L.append(f"- `{r['endpoint']}`  — hints: {', '.join(r['hints'])}")
        L.append("")

    L.append("## Cross-principal probe plan (own principals only — QL6)")
    L.append("")
    L.append(f"{plan.summary}")
    L.append("")
    for p in plan.probe[:20]:
        L.append(f"- `{p['principal']}` GET `{p['path']}`  "
                 f"(object `{p.get('_object_id','?')}` held by `{p.get('_replayed_from','?')}`)")
    if len(plan.probe) > 20:
        L.append(f"- … and {len(plan.probe) - 20} more")
    L.append("")

    if flags:
        L.append("## Feature flags observed (report-only)")
        L.append("")
        L.append(", ".join(f"`{f}`" for f in flags[:40]))
        L.append("")

    L.append("---")
    L.append("Feed the emitted `spec.json` to ONYX: `python -m authpath scan spec.json --out reports/`")
    return "\n".join(L) + "\n"
