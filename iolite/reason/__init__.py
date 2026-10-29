"""
IOLITE · reason — grey-box authorization reasoning engine (the "brain").

It sits BETWEEN acquisition (IOLITE) and confirmation (ONYX):

    IOLITE (eyes: acquires surface)
        → reason (reconstructs INTENT I, measures ENFORCEMENT E,
                  hunts I △ E + invariant violations + negated assumptions)
        → ONYX (proof: Δstate confirms or discards every candidate)

Design law (QL5, one-way): reason PROPOSES candidates; ONYX DISPOSES. This module
holds no verdict. Every candidate carries the ONYX EffectClass it will be confirmed
under, its provenance, and a confidence — never a decision.

Honesty ceiling (named walls, never hidden):
  * Undecidability (Rice): no tool is COMPLETE. reason searches to a BOUNDED depth
    and maximizes recall by out-reasoning the defender, it never guarantees "all".
  * Reconstruction bound: INTENT is rebuilt from legally-observed leakage; where
    intent did not leak and surface was unreached, reason is silent (false negatives
    possible, false positives impossible — ONYX guards that).

Pure stdlib. Deterministic (QL4). Additive-only (never weakens IOLITE or ONYX).
"""

from __future__ import annotations

__reason_version__ = "0.14.0"   # + opt-in acquisition/feedback chain (spec._reason.acquisition)

# The honesty ceiling, carried into every report (P7).
BOUNDED_DEPTH_K = 3          # seed searches single-step + declared-surface reach
NAMED_WALLS = (
    "undecidability: no completeness guarantee — superiority, not omniscience",
    "reconstruction-bound: intent rebuilt from observed leakage only",
    "state-explosion: search bounded to depth k (real authz chains are short)",
    "legal: own principals only, in-scope only, ONYX-confirmed, non-destructive",
)

from .intent import AccessClass, IntentRule, infer_intent          # noqa: E402
from .intent_graph import refine as refine_intent                  # noqa: E402
from .signals import IntentSignals, endpoint_signals, jwt_role_based  # noqa: E402
from .leakage import mine_leakage, feature_flags                   # noqa: E402
from .workflow_intent import (DeclaredGuard, mine_workflow_guards,  # noqa: E402
                              mine_enums)
from .sequence import run_sequence                                 # noqa: E402
from .coverage import coverage, CoverageReport                     # noqa: E402
from .writeup import Writeup, writeup, writeups_from_report, quickwin_writeup  # noqa: E402
from .novelty import NoveltyScore, score_novelty, novelty_map, priority  # noqa: E402
from . import quickwins                                            # noqa: E402
from .quickwins import QuickWin                                    # noqa: E402
from .enforcement import EnfObservation, observe_enforcement       # noqa: E402
from .differ import ReasonCandidate, diff_intent_enforcement       # noqa: E402
from .engine import (ReasonReport, reason, candidates_to_plan,      # noqa: E402
                     build_reason_spec, spec_from_candidates,
                     AcquisitionReport, run_acquisition)
from .report import render as render_report                        # noqa: E402
from .oracle import (Oracle, OracleVerdict, StaticOracle,          # noqa: E402
                     LiveOnyxOracle, SimulatedOracle)
from .cegar import CegarTrace, CegarRound, refine_search           # noqa: E402
from .amplify import (ImpactScore, score_candidate, amplify,        # noqa: E402
                      ranked as ranked_by_impact, scale_probes)
from .collision import CollisionScore, collision_score             # noqa: E402
from .readiness import (Readiness, assess as assess_readiness,     # noqa: E402
                        assess_report as assess_readiness_report,
                        summary as readiness_summary)
from .econ import (EconEntry, ProgramStats, Recommendation,        # noqa: E402
                   load_ledger, save_ledger, program_stats,
                   recommend as econ_recommend, portfolio_summary)
from .kb import (KB, load_kb, save_kb, update_from as kb_update,    # noqa: E402
                 kb_signals, fresh_endpoints, regressions)

__all__ = [
    "ImpactScore", "score_candidate", "amplify", "ranked_by_impact", "scale_probes",
    "AccessClass", "IntentRule", "infer_intent",
    "IntentSignals", "endpoint_signals", "jwt_role_based", "mine_leakage",
    "feature_flags", "coverage", "CoverageReport",
    "DeclaredGuard", "mine_workflow_guards", "mine_enums", "run_sequence",
    "refine_intent",
    "Writeup", "writeup", "writeups_from_report", "quickwin_writeup",
    "NoveltyScore", "score_novelty", "novelty_map", "priority",
    "quickwins", "QuickWin",
    "EnfObservation", "observe_enforcement",
    "ReasonCandidate", "diff_intent_enforcement",
    "ReasonReport", "reason", "candidates_to_plan", "build_reason_spec",
    "spec_from_candidates", "render_report",
    "AcquisitionReport", "run_acquisition",
    "ConfirmedFinding", "feedback_reweight", "feedback_reweight_capture",
    "Oracle", "OracleVerdict", "StaticOracle", "LiveOnyxOracle", "SimulatedOracle",
    "CegarTrace", "CegarRound", "refine_search",
    "CollisionScore", "collision_score",
    "Readiness", "assess_readiness", "assess_readiness_report", "readiness_summary",
    "EconEntry", "ProgramStats", "Recommendation", "load_ledger", "save_ledger",
    "program_stats", "econ_recommend", "portfolio_summary",
    "KB", "load_kb", "save_kb", "kb_update", "kb_signals", "fresh_endpoints", "regressions",
    "BOUNDED_DEPTH_K", "NAMED_WALLS", "__reason_version__",
]


# feedback.py imports back into intent.relation_model, which itself imports this package at
# load time — so exposing these eagerly would create an import cycle. Resolve them lazily
# (PEP 562), after both packages are fully initialised.
def __getattr__(name):
    if name in ("ConfirmedFinding", "feedback_reweight", "feedback_reweight_capture"):
        from . import feedback as _fb
        return {"ConfirmedFinding": _fb.ConfirmedFinding,
                "feedback_reweight": _fb.reweight,
                "feedback_reweight_capture": _fb.reweight_capture}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
