"""
reason · report — a human-checkable dossier of the reasoning run.

States the intent it reconstructed, the I△E candidates and their ONYX effect, the
active/planned catalog, and the honesty ceiling. Never a verdict (QL5).
"""

from __future__ import annotations

from .engine import ReasonReport


def render(rep: ReasonReport) -> str:
    L: list[str] = []
    c = rep.counts
    L.append("# IOLITE · reason — grey-box authorization reasoning\n")
    L.append(f"reason v{c.get('reason_version')} · endpoints={c.get('endpoints')} · "
             f"intent-restricted={c.get('intent_restricted')} · "
             f"principals={c.get('principals')} · candidates={c.get('candidates')} · "
             f"depth k={c.get('depth_k')}\n")

    bands = rep.by_band()
    L.append(f"\nimpact bands: critical={bands['critical']} · high={bands['high']} · "
             f"medium={bands['medium']} · low={bands['low']}\n")

    L.append("\n## Candidates — ranked by EXPECTED PAYOUT (impact × novelty; ONYX confirms each)\n")
    if not rep.candidates:
        L.append("  (none from this surface — reconstruction is bounded by observed leakage)\n")
    for i, cand in enumerate(rep.ranked_by_priority(), 1):
        sc = rep.impact.get(cand.cand_key)
        nv = rep.novelty.get(cand.cand_key)
        band = f"{sc.band.upper()}({sc.score})" if sc else "?"
        prio = rep.priority_of(cand)
        tag = f"P{prio}·N{nv.score}" if nv else f"P{prio}"
        L.append(f"{i:>2}. [{tag}] [{band}] [{cand.onyx_effect}] {cand.method} {cand.path}")
        L.append(f"     gap={cand.gap_kind} · intent={cand.intent_class}"
                 f"({cand.intent_confidence}) · probes={','.join(cand.probe_pids)}"
                 + (f" · depth={cand.depth}" if cand.depth > 1 else ""))
        L.append(f"     why: {cand.rationale}")
        if sc:
            L.append(f"     impact: {sc.narrative}")
        if nv and nv.reasons:
            L.append(f"     novelty: {'; '.join(nv.reasons)}")

    if rep.quickwins:
        L.append("\n## Quick wins — passive, payable now (NOT ONYX-confirmed; self-evident evidence)\n")
        for i, q in enumerate(rep.quickwins, 1):
            lead = " [lead — verify]" if q.is_lead else ""
            L.append(f"{i:>2}. [{q.severity.upper()}] {q.kind}{lead}")
            L.append(f"     {q.where} · {q.evidence} · confidence={q.confidence}")

    L.append("\n## Family breakdown\n")
    for fam, n in rep.by_family().items():
        L.append(f"  {fam:<26} {n}")

    L.append("\n## Invariant catalog (transplanted science)\n")
    for inv in rep.invariants:
        mark = "●" if inv["status"] == "active" else "○"
        L.append(f"  {mark} {inv['name']:<26} [{inv['status']}]  — {inv['science']}")

    L.append("\n## Assumption library (HAZOP — negate the unquestioned)\n")
    for a in rep.assumptions:
        mark = "●" if a["status"] == "active" else "○"
        L.append(f"  {mark} {a['name']:<26} [{a['status']}]  — {a['assumption']}")

    cov = rep.coverage
    L.append("\n## Coverage (recall signal — precision is ONYX's, recall is yours)\n")
    L.append(f"  restricted endpoints covered: {cov.covered}/{cov.restricted} "
             f"({cov.pct*100:.0f}%)")
    if cov.untested:
        L.append(f"  untested restricted ({len(cov.untested)}) — acquire to raise recall:")
        for k in cov.untested[:8]:
            L.append(f"    · {k}")
    if cov.method_gaps:
        L.append(f"  CRUD method gaps ({len(cov.method_gaps)}) — likely-unobserved surface:")
        for g in cov.method_gaps[:6]:
            L.append(f"    · {g}")

    L.append("\n## Honesty ceiling (named walls)\n")
    for w in rep.walls:
        L.append(f"  · {w}")
    L.append("\nreason PROPOSES; ONYX DISPOSES. False positives are impossible "
             "(ONYX Δstate); false negatives are possible where intent did not leak.\n")
    return "\n".join(L)
