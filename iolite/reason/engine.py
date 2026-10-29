"""
reason · engine — orchestrate I, E, the differ, the invariant catalog and the
assumption library into a ReasonReport, and translate candidates into an ONYX-ready
plan + enriched spec.

Flow (all offline, deterministic, own-principals-only):
  infer_intent (I) → observe_enforcement (E) → diff I△E
                   → run_invariants → run_assumptions
                   → candidates → ReplayPlan (reusing IOLITE's emitter)
                   → ONYX spec (+ a self-describing `_reason` block)

reason PROPOSES; ONYX DISPOSES (QL5). Nothing here decides a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import SurfaceModel
from ..replay import ReplayPlan, _seed
from ..onyx_spec import build_spec
from ..roe import Engagement
from . import BOUNDED_DEPTH_K, NAMED_WALLS, __reason_version__
from .intent import infer_intent, IntentRule
from .enforcement import observe_enforcement
from .differ import diff_intent_enforcement, ReasonCandidate
from .invariants import run_invariants, catalog_status as inv_status
from .assumptions import run_assumptions, catalog_status as asm_status
from .workflow_intent import mine_workflow_guards, catalog_status as wf_status
from .sequence import run_sequence
from .amplify import amplify
from .coverage import coverage, CoverageReport
from .novelty import novelty_map, priority as _priority
from . import quickwins as _quickwins


@dataclass
class ReasonReport:
    intent: dict[str, IntentRule]
    candidates: list[ReasonCandidate]
    invariants: list[dict]
    assumptions: list[dict]
    counts: dict = field(default_factory=dict)
    walls: tuple = NAMED_WALLS
    impact: dict = field(default_factory=dict)   # cand_key -> ImpactScore
    coverage: CoverageReport = field(default_factory=CoverageReport)
    novelty: dict = field(default_factory=dict)  # cand_key -> NoveltyScore
    quickwins: list = field(default_factory=list)  # passive QuickWin findings
    guards: list = field(default_factory=list)   # DeclaredGuard[] (workflow, opt-in)
    acquisition: "AcquisitionReport | None" = None  # opt-in acquisition/feedback chain

    def by_family(self) -> dict[str, int]:
        d: dict[str, int] = {}
        for c in self.candidates:
            d[c.family] = d.get(c.family, 0) + 1
        return dict(sorted(d.items()))

    def by_band(self) -> dict[str, int]:
        d: dict[str, int] = {}
        for sc in self.impact.values():
            d[sc.band] = d.get(sc.band, 0) + 1
        return {b: d.get(b, 0) for b in ("critical", "high", "medium", "low")}

    def priority_of(self, c: ReasonCandidate) -> int:
        return _priority(c, self.impact.get(c.cand_key), self.novelty.get(c.cand_key))

    def ranked(self) -> list[ReasonCandidate]:
        return sorted(self.candidates,
                      key=lambda c: (-self.impact[c.cand_key].score, c.cand_key)
                      if c.cand_key in self.impact else (0, c.cand_key))

    def ranked_by_priority(self) -> list[ReasonCandidate]:
        """impact + novelty — maximises EXPECTED PAYOUT (validity × originality)."""
        return sorted(self.candidates, key=lambda c: (-self.priority_of(c), c.cand_key))


def _dedup(cands: list[ReasonCandidate]) -> list[ReasonCandidate]:
    seen, out = set(), []
    for c in cands:
        sig = (c.endpoint_key, c.path, c.family, c.object_id, tuple(c.probe_pids))
        if sig in seen:
            continue
        seen.add(sig)
        out.append(c)
    return out


def _load_texts(paths) -> list[tuple[str, str]]:
    """Best-effort (text, locator) pairs; a missing/unreadable file is skipped (QL2)."""
    out: list[tuple[str, str]] = []
    for p in paths or []:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                out.append((fh.read(), p))
        except OSError:
            continue
    return out


def _mine_guards(model: SurfaceModel, inputs):
    """Mine DECLARED workflow guards from the operator's captured artifacts.
    Never fatal (QL2). Returns [] when nothing is declared (honest floor)."""
    if inputs is None:
        return []
    try:
        js_pairs = _load_texts(list(getattr(inputs, "js_files", []) or []) +
                               list(getattr(inputs, "sourcemap_files", []) or []) +
                               list(getattr(inputs, "archived_js_files", []) or []))
        gql = _load_texts([getattr(inputs, "graphql_file", "") or ""] if
                          getattr(inputs, "graphql_file", "") else [])
        oapi = _load_texts([getattr(inputs, "openapi_file", "") or ""] if
                           getattr(inputs, "openapi_file", "") else [])
        return mine_workflow_guards(
            model, js_texts=[t for t, _ in js_pairs],
            js_locators=[loc for _, loc in js_pairs],
            graphql_text=gql[0][0] if gql else "",
            openapi_text=oapi[0][0] if oapi else "")
    except Exception:      # noqa: BLE001 — guard mining is best-effort, never fatal
        return []


def reason(model: SurfaceModel, inputs=None, mobile_paths=None, commits_paths=None,
           with_workflow: bool = False, rich_intent: bool = False,
           with_acquisition: bool = False, archived_urls=None, engagement=None,
           sender=None, confirmed_findings=None) -> ReasonReport:
    """Run the full reasoning pass. `inputs` (optional pipeline.Inputs) lets the
    engine mine raw OpenAPI/GraphQL/HAR/JS-feature-flag leakage to deepen intent I;
    `mobile_paths`/`commits_paths` add the operator's own app strings and public
    commit logs as further legal leakage.

    `with_workflow` (opt-in, default OFF ⇒ byte-identical to the prior behaviour)
    additionally mines DECLARED workflow guards and emits state-indexed gate-skip /
    privileged-transition hypotheses (Point 1). When no guard is declared it adds
    nothing."""
    leakage = None
    if inputs is not None or mobile_paths or commits_paths:
        try:
            from .leakage import mine_leakage
            js = list(getattr(inputs, "js_files", []) or []) + \
                list(getattr(inputs, "sourcemap_files", []) or []) + \
                list(getattr(inputs, "archived_js_files", []) or [])
            leakage = mine_leakage(
                model,
                openapi_path=getattr(inputs, "openapi_file", "") or "",
                graphql_path=getattr(inputs, "graphql_file", "") or "",
                har_paths=list(getattr(inputs, "har_files", []) or []),
                js_paths=js, mobile_paths=list(mobile_paths or []),
                commits_paths=list(commits_paths or []))
        except Exception:      # noqa: BLE001 — leakage is best-effort, never fatal
            leakage = None
    intent = infer_intent(model, leakage=leakage, joint=rich_intent)
    enf = observe_enforcement(model)
    cands: list[ReasonCandidate] = []
    cands += diff_intent_enforcement(model, intent, enf)
    cands += run_invariants(model, intent, enf)
    cands += run_assumptions(model, intent, enf)
    guards = _mine_guards(model, inputs) if with_workflow else []
    if guards:
        cands += run_sequence(model, intent, enf, guards)
    cands = _dedup(cands)
    cands.sort(key=lambda c: (c.family, c.endpoint_key, c.object_id))

    restricted = sum(1 for r in intent.values() if r.rank >= 2)
    counts = {
        "endpoints": len(model.endpoints),
        "intent_restricted": restricted,
        "candidates": len(cands),
        "principals": len(model.principals),
        "depth_k": BOUNDED_DEPTH_K,
        "reason_version": __reason_version__,
        "leakage_hints": len(leakage or {}),
        "workflow_guards": len(guards),
        "rich_intent": bool(rich_intent),
    }
    rep = ReasonReport(intent=intent, candidates=cands,
                       invariants=inv_status(), assumptions=asm_status(),
                       counts=counts, impact=amplify(cands, model),
                       coverage=coverage(model, intent, cands),
                       novelty=novelty_map(cands, model),
                       quickwins=_quickwins.detect_from_inputs(inputs),
                       guards=guards)
    rep.counts["by_family"] = rep.by_family()
    rep.counts["by_band"] = rep.by_band()
    rep.counts["coverage_pct"] = rep.coverage.pct
    rep.counts["quickwins"] = len(rep.quickwins)
    # opt-in acquisition/feedback chain (default OFF ⇒ output byte-identical to before).
    # It may fold mobile-only endpoints into `model`, so it runs after the base pass that
    # defines the byte-identical default, and its results live under rep.acquisition only.
    if with_acquisition or mobile_paths or archived_urls or confirmed_findings:
        rep.acquisition = run_acquisition(
            model, inputs, mobile_paths=mobile_paths, archived_urls=archived_urls,
            engagement=engagement, sender=sender, confirmed_findings=confirmed_findings)
        acq = rep.acquisition
        rep.counts["acquisition"] = {
            "architecture": acq.architecture.get("topology", "") if acq.architecture else "",
            "authz_pattern": acq.architecture.get("authz_pattern", "") if acq.architecture else "",
            "pressure_points": len(acq.architecture.get("pressure_points", [])) if acq.architecture else 0,
            "federation_present": bool(acq.federation.get("present")) if acq.federation else False,
            "mobile_only": len(acq.mobile.get("mobile_only", [])) if acq.mobile else 0,
            "ghosts": len(acq.ghosts), "hidden_leads": len(acq.hidden_leads),
            "existence_hits": len(acq.existence_hits), "capture_steps": len(acq.capture_plan),
            "feedback_applied": acq.feedback_applied,
        }
    return rep


@dataclass
class AcquisitionReport:
    """The acquisition & feedback chain, folded into reason() opt-in. Each piece is
    propose-only (QL5), deterministic (QL4), own-evidence/passive (QL6). Default OFF, so
    the base reason() output is byte-identical until the operator asks for it."""
    architecture: dict = field(default_factory=dict)          # topology/authz/identity + pressure points
    federation: dict = field(default_factory=dict)            # identity surface summary
    mobile: dict = field(default_factory=dict)                # client-axis surface (mobile-only delta)
    ghosts: list = field(default_factory=list)                # time-axis: authz-ranked archived ghosts
    hidden_leads: list = field(default_factory=list)          # existence-oracle hypotheses (offline leads)
    existence_hits: list = field(default_factory=list)        # confirmed-live hidden paths (live ROE only)
    capture_plan: list = field(default_factory=list)          # coverage-guided prioritised capture plan
    feedback_applied: int = 0                                 # # candidates re-weighted by a confirmed finding
    notes: list = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "architecture": self.architecture,
            "federation": self.federation,
            "mobile": self.mobile,
            "ghosts": self.ghosts[:40],
            "hidden_leads": self.hidden_leads[:40],
            "existence_hits": self.existence_hits[:40],
            "capture_plan": self.capture_plan[:40],
            "feedback_applied": self.feedback_applied,
            "notes": self.notes,
            "note": "acquisition PROPOSES surface & order; ONYX DISPOSES every finding by "
                    "Δstate. Passive/own-evidence; hidden paths are confirmed for EXISTENCE "
                    "only, fail-closed, under ROE (QL5/QL6).",
        }


def _confirmed_findings(raw) -> list:
    """Normalise prior ONYX verdicts into feedback.ConfirmedFinding (the adaptive-loop input).
    Accepts ConfirmedFinding objects or plain dicts ({family/cls, path, object_type, host,
    method}); anything unusable is skipped (never fatal)."""
    from .feedback import ConfirmedFinding
    out = []
    for f in raw or []:
        if isinstance(f, ConfirmedFinding):
            out.append(f); continue
        if isinstance(f, dict):
            out.append(ConfirmedFinding(
                family=str(f.get("family") or f.get("cls") or f.get("effect") or ""),
                path=str(f.get("path") or ""),
                object_type=str(f.get("object_type") or f.get("object") or ""),
                host=str(f.get("host") or ""),
                method=str(f.get("method") or "GET")))
    return out


def run_acquisition(model: SurfaceModel, inputs=None, *, mobile_paths=None,
                    archived_urls=None, engagement=None, sender=None,
                    confirmed_findings=None) -> AcquisitionReport:
    """Compose the full acquisition/feedback chain over an already-acquired surface.

    Deterministic, offline by default (nothing is fetched): the existence oracle only sends
    SAFE probes when `sender` + an attested, automation-permitted engagement are supplied,
    exactly as existence_oracle.probe_existence requires (fail-closed). `confirmed_findings`
    (prior ONYX verdicts) activates the feedback loop, re-weighting discovery/capture toward
    proven neighbourhoods. Never fatal — any piece that cannot run is skipped with a note."""
    rep = AcquisitionReport()
    try:
        from ..intent.relation_model import build_lattice
        from ..intent.federation import mine_federation
        from ..intent.architecture import model_architecture, summarize as _arch_summary
        from ..intent.existence_oracle import hidden_path_hypotheses, probe_existence
        from ..intent.capture_plan import plan_capture
        from ..mobile_mine import mine_mobile
        from .ghost_triage import ghosts_from_url_feed, triage_ghosts, probe_targets
        from . import feedback as _feedback
    except Exception as e:  # noqa: BLE001 — chain is additive; its absence must never break reason()
        rep.notes.append(f"acquisition chain unavailable: {e!r}")
        return rep

    lat = build_lattice(model)
    findings = _confirmed_findings(confirmed_findings)

    # ---- identity / architecture (the authz machine + where to press) --------------
    try:
        texts = [t for t, _ in _load_texts(
            list(getattr(inputs, "js_files", []) or []) +
            list(getattr(inputs, "sourcemap_files", []) or []) +
            list(getattr(inputs, "archived_js_files", []) or []) +
            list(getattr(inputs, "har_files", []) or []))] if inputs is not None else []
        fed = mine_federation(model, texts=texts)
        arch = model_architecture(model, lattice=lat, federation=fed)
        rep.federation = {"present": fed.present, "provider": fed.provider,
                          "protocol": fed.protocol, "issuer": fed.issuer,
                          "identity_claims": fed.identity_claims,
                          "endpoints": fed.endpoints, "leads": fed.leads,
                          "hypotheses": fed.hypotheses}
        rep.architecture = _arch_summary(arch)
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"architecture/federation skipped: {e!r}")

    # ---- mobile (client axis): fold mobile-only endpoints into the live surface -----
    mobile_eps = []
    try:
        blobs = [(t, p) for t, p in _load_texts(list(mobile_paths or []))]
        if blobs:
            web_keys = set(model.endpoints.keys())
            mrep = mine_mobile(blobs, known_hosts=model.hosts_seen, web_keys=web_keys)
            for ep in mrep.endpoints:
                if ep.key not in model.endpoints:
                    model.add_endpoint(ep)          # the rest of the pipeline now sees them
                    mobile_eps.append(model.endpoints[ep.key])
            rep.mobile = {"endpoints": len(mrep.endpoints), "mobile_only": mrep.mobile_only,
                          "hosts_main": sorted(mrep.hosts_main),
                          "hosts_partner": sorted(mrep.hosts_partner),
                          "hosts_staging": sorted(mrep.hosts_staging),
                          "summary": mrep.summary}
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"mobile mining skipped: {e!r}")

    # ---- ghosts (time axis): rank archived-only surface by authz risk ---------------
    ghost_eps = []
    try:
        live_keys = {k for k in model.endpoints if k not in model.ghost_keys}
        ghost_eps = [model.endpoints[k] for k in model.ghost_keys if k in model.endpoints]
        ghost_eps += ghosts_from_url_feed(archived_urls, live_keys)   # raw wayback/gau feed
        ranked = triage_ghosts(ghost_eps, current_keys=live_keys)
        rep.ghosts = [{"key": r.key, "score": r.score, "reasons": r.reasons} for r in ranked]
        ghost_probe = probe_targets(ranked)
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"ghost triage skipped: {e!r}")
        ghost_probe = []

    # ---- existence oracle: hidden siblings (+ ghost probes), fail-closed ------------
    try:
        hyps = hidden_path_hypotheses(model)
        known = {getattr(h, "path", "") for h in hyps}
        from ..intent.existence_oracle import PathHypothesis
        hyps += [PathHypothesis(path=p, reason="ghost confirmed worth probing live")
                 for p in ghost_probe if p not in known]
        host = getattr(model, "host", "") or ""
        pr = probe_existence(hyps, engagement=engagement, sender=sender, host=host)
        rep.hidden_leads = [{"path": h.path, "reason": getattr(h, "reason", "")} for h in pr.leads]
        rep.existence_hits = [{"path": h.path, "status": h.status, "verdict": h.verdict,
                               "reason": h.reason} for h in pr.hits]
        existence_hits = pr.hits
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"existence oracle skipped: {e!r}")
        existence_hits = []

    # ---- capture plan (coverage-guided), with existence hits folded in --------------
    steps = []
    try:
        steps = plan_capture(model, lattice=lat, existence_hits=existence_hits)
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"capture plan skipped: {e!r}")

    # ---- feedback loop: a confirmed ONYX finding re-weights discovery & capture -----
    try:
        if findings:
            discovery = list(ghost_eps) + list(mobile_eps)
            before = {id(ep): getattr(ep, "risk", 0) for ep in discovery}
            _feedback.reweight(discovery, findings, host=getattr(model, "host", ""))
            rep.feedback_applied = sum(
                1 for ep in discovery if getattr(ep, "risk", 0) != before.get(id(ep), 0))
            steps = _feedback.reweight_capture(steps, findings)
            rep.ghosts = sorted(rep.ghosts, key=lambda g: -g["score"])  # reflect any re-rank
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"feedback loop skipped: {e!r}")

    rep.capture_plan = [{"object_type": s.object_type, "flow": s.flow,
                         "methods": s.methods, "accounts_needed": s.accounts_needed,
                         "roles": s.roles, "unlocks": s.unlocks,
                         "est_tests": s.est_tests, "why": s.why} for s in steps]
    return rep


def candidates_to_plan(model: SurfaceModel, cands: list[ReasonCandidate],
                       max_probes: int = 500) -> ReplayPlan:
    """Seed = your legitimate reads (envelopes). Probe = reason candidates, round-robin
    by endpoint so no hot endpoint starves the rest. Deterministic (QL4)."""
    plan = ReplayPlan(seed=_seed(model))
    groups: dict[str, list[dict]] = {}
    for c in cands:
        for item in c.to_probe_items():
            groups.setdefault(c.endpoint_key, []).append(item)
    ordered = sorted(groups)
    idx = {k: 0 for k in ordered}
    remaining = max(0, max_probes)
    progress = True
    while remaining > 0 and progress:
        progress = False
        for k in ordered:
            if remaining <= 0:
                break
            if idx[k] >= len(groups[k]):
                continue
            plan.probe.append(groups[k][idx[k]])
            idx[k] += 1
            remaining -= 1
            progress = True
    return plan


def spec_from_candidates(model: SurfaceModel, cands, engagement: Engagement,
                         max_probes: int = 500, redact: bool = True) -> dict:
    """Build an ONYX spec from an arbitrary candidate list (used by the CEGAR oracle
    to test a single round's batch). Reuses IOLITE's emitter unchanged."""
    plan = candidates_to_plan(model, list(cands), max_probes=max_probes)
    scope = engagement.scope_config()
    return build_spec(model, plan, scope, engagement=engagement, redact=redact)


def build_reason_spec(model: SurfaceModel, rep: ReasonReport, engagement: Engagement,
                      max_probes: int = 500, redact: bool = True) -> dict:
    """Reuse IOLITE's ONYX emitter, then attach a self-describing `_reason` block.
    ONYX ignores unknown keys, so the spec runs as-is and every candidate is still
    decided by ONYX Δstate (QL5)."""
    plan = candidates_to_plan(model, rep.candidates, max_probes=max_probes)
    scope = engagement.scope_config()
    spec = build_spec(model, plan, scope, engagement=engagement, redact=redact)
    spec["_reason"] = {
        "version": __reason_version__,
        "counts": rep.counts,
        "walls": list(NAMED_WALLS),
        "intent": {k: {"class": r.access_class.value, "confidence": r.confidence,
                       "signals": list(r.signals)}
                   for k, r in rep.intent.items()},
        "candidates": [
            {"endpoint": c.endpoint_key, "path": c.path, "method": c.method,
             "gap": c.gap_kind, "intent": c.intent_class, "confidence": c.intent_confidence,
             "onyx_effect": c.onyx_effect, "probes": c.probe_pids,
             "object_id": c.object_id, "why": c.rationale,
             "impact_band": rep.impact[c.cand_key].band if c.cand_key in rep.impact else "",
             "impact_score": rep.impact[c.cand_key].score if c.cand_key in rep.impact else 0,
             "novelty": rep.novelty[c.cand_key].score if c.cand_key in rep.novelty else 0,
             "priority": rep.priority_of(c),
             **({"pre_state": dict(c.pre_state), "declared_gate": c.required_predecessor}
                if c.pre_state else {})}
            for c in rep.ranked_by_priority()],
        "impact_bands": rep.by_band(),
        "quickwins": [
            {"kind": q.kind, "severity": q.severity, "where": q.where,
             "evidence": q.evidence, "confidence": q.confidence, "lead": q.is_lead}
            for q in rep.quickwins],
        "invariants": rep.invariants,
        "assumptions": rep.assumptions,
        "coverage": {"restricted": rep.coverage.restricted, "covered": rep.coverage.covered,
                     "pct": rep.coverage.pct, "untested": rep.coverage.untested,
                     "method_gaps": rep.coverage.method_gaps},
        "note": "reason PROPOSES; ONYX DISPOSES. Every candidate is a hypothesis "
                "confirmed only by ONYX Δstate. No verdict is asserted here (QL5).",
    }
    # DECLARED workflow guards → a transcription-grade reference for ONYX's
    # StateGateLaw (Point 1). Emitted only when guards were mined, so the default
    # (no-workflow) spec stays byte-identical. ONYX ignores unknown keys.
    if rep.guards:
        spec["_reason"]["declared_state_gates"] = wf_status(rep.guards)
    # acquisition/feedback chain → self-describing block (emitted only when it ran, so the
    # default spec stays byte-identical). ONYX ignores unknown keys; every hidden path is
    # confirmed for EXISTENCE only and every finding still decided by ONYX Δstate (QL5).
    if rep.acquisition is not None:
        spec["_reason"]["acquisition"] = rep.acquisition.summary()
    return spec
