"""
iolite.intent — interventional authorization-intent engine (Wall-1).

ADDITIVE and OPT-IN: importing or running this package changes nothing about
IOLITE's default behaviour (QL4 byte-identical). Deterministic, no LLM/ML in the
decision path. It reconstructs authorization intent by INTERVENTION (create
objects as the operator's own principals, using the target's own affordances)
and proves an over-permission by a value-presence Δstate — never a status code.

Division of labour (unchanged): IOLITE acquires/proposes, ONYX's Δstate confirms.
This module is slated to fold into `iolite.reason` as the intent-reconstruction
core once the remaining walls (Wall-3 safe mutation, ONYX confirmer wiring) land.
See docs/notes/WALL1.md and docs/notes/WALL1_STATE.md.
"""
from .engine import run_target, to_markdown, Finding, ScopeGuard  # noqa: F401

# v1.15.0 — the relational authorization lattice + wide divergence enumerator + the
# sound metamorphic oracle, composed by the WIRED kill-chain (runs on a real
# SurfaceModel, not an in-process demo). Imported lazily by callers; re-exported here
# for convenience. Still additive and opt-in (QL4 byte-identical default behaviour).
from . import relation_model, divergence, metamorphic, kill_chain  # noqa: F401,E402
# v1.16 — evidence capture, schema learning, offline corroboration, GraphQL techniques
from . import capture, schema_learn, corroborate, graphql_probe  # noqa: F401,E402
# v1.17 — real HAR ingestion (with responses), the field hunt driver, dossier reporting
from . import har_capture, hunt, dossier  # noqa: F401,E402
# v1.18 — scan WHILE you browse: the incremental live session + the loopback collector
from . import live_session, collector  # noqa: F401,E402
# v1.19 — deep response reading + contrast-learning intent builder
from . import observation, policy_learn  # noqa: F401,E402
# v1.20 — defense sensing + adaptive pacing + a defense-aware task executor
from . import defense, pacer, executor  # noqa: F401,E402
# v1.21 — the defense-aware live replay confirmer (leads → probes → value-presence)
from . import confirm  # noqa: F401,E402
# v1.22 — auto target.json generator + the live browser dashboard (served by the collector)
from . import target_gen  # noqa: F401,E402

__all__ = ["run_target", "to_markdown", "Finding", "ScopeGuard",
           "relation_model", "divergence", "metamorphic", "kill_chain",
           "capture", "schema_learn", "corroborate", "graphql_probe",
           "har_capture", "hunt", "dossier", "live_session", "collector",
           "observation", "policy_learn", "defense", "pacer", "executor", "confirm",
           "target_gen"]
