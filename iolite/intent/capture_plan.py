"""
capture_plan.py — turn capture from luck into engineering (the coverage-guided plan).

The whole chain's ceiling is the operator's capture session: if they captured reads but
never a create/share/delete, the write/BOPLA/rebinding families have nothing to reason over
— and `reason.coverage` can only REPORT that silence. This planner acts on it: for every
object type it diffs the write surface the target EXPOSES against the flows actually
CAPTURED, and emits a PRIORITISED plan — which flow, for which object type, with how many
accounts — each step ranked by the number of authorization tests it would UNLOCK, and
naming the ONYX families it opens. Hidden endpoints confirmed by the existence oracle are
folded in as the highest-priority capture targets.

Deterministic (QL4). Measures and plans; proposes, never adjudicates (QL5).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .relation_model import build_lattice, _obj_type_of_path

_WRITE = ("POST", "PUT", "PATCH", "DELETE")


@dataclass
class CaptureStep:
    object_type: str
    flow: str                                  # the capture action to perform
    methods: list = field(default_factory=list)
    accounts_needed: int = 2
    roles: str = "2 peers you own (owner + would-be attacker)"
    unlocks: list = field(default_factory=list)   # ONYX families this capture opens
    est_tests: int = 0                          # authz tests unlocked (ranking key)
    why: str = ""


def _methods_by_type(pairs):
    out: dict = {}
    for method, path in pairs:
        t = _obj_type_of_path(path)
        if t:
            out.setdefault(t, set()).add(method.upper())
    return out


def plan_capture(model, *, lattice=None, existence_hits=None) -> list:
    lat = lattice or build_lattice(model)

    surface = _methods_by_type(
        (ep.method, ep.path) for ep in getattr(model, "endpoints", {}).values())
    captured = _methods_by_type(
        (a.method, a.path) for a in getattr(model, "accesses", []))

    steps: list = []
    for otype in sorted(lat.types):
        tf = lat.types[otype]
        surf_m = surface.get(otype, set())
        cap_m = captured.get(otype, set())
        gap_writes = sorted(m for m in _WRITE if m in surf_m and m not in cap_m)
        read_uncaptured = ("GET" in surf_m and "GET" not in cap_m)
        if not gap_writes and not read_uncaptured:
            continue

        n_sauth = sum(1 for c in tf.fields.values() if c == "server_auth")
        n_own = sum(1 for c in tf.fields.values() if c == "ownership")
        has_tenant = any(o.tenant for o in lat.objects.values() if o.otype == otype)

        unlocks, est = [], 0
        if read_uncaptured:
            unlocks.append("read_bola"); est += 1
        if gap_writes:
            unlocks.append("action_bola"); est += len(gap_writes)
            if n_sauth:
                unlocks.append("bopla_field"); est += n_sauth
            if n_own:
                unlocks.append("rebinding"); est += n_own
        if has_tenant:
            unlocks.append("tenant"); est += 1

        accounts = 2
        roles = "2 peers you own (owner + would-be attacker)"
        if has_tenant:
            roles = "2 accounts in DIFFERENT tenants you own"
        flow = (f"capture {'+'.join(gap_writes) or 'GET'} on a '{otype}' you own, then the "
                f"SAME request as a second principal")
        why = (f"'{otype}' exposes {sorted(surf_m)} but you captured only {sorted(cap_m) or '[]'}; "
               f"capturing the missing flow unlocks {unlocks}")
        steps.append(CaptureStep(object_type=otype, flow=flow, methods=gap_writes or ["GET"],
                                 accounts_needed=accounts, roles=roles, unlocks=sorted(set(unlocks)),
                                 est_tests=est, why=why))

    # fold in existence-oracle hits: a hidden endpoint that EXISTS but was never captured is
    # the single highest-value capture target (you cannot test what you never recorded).
    for h in (existence_hits or []):
        path = getattr(h, "path", str(h))
        otype = _obj_type_of_path(path) or "(hidden)"
        verdict = getattr(h, "verdict", "exists")
        steps.append(CaptureStep(
            object_type=otype,
            flow=f"authenticate and capture a request to the discovered hidden endpoint {path}",
            methods=["GET"], accounts_needed=2,
            roles="2 peers you own (owner + would-be attacker)",
            unlocks=["read_bola", "action_bola"],
            est_tests=10 + (5 if verdict == "protected" else 0),
            why=f"existence oracle confirmed {path} EXISTS ({verdict}) yet it is absent from "
                f"every capture → acquire it first"))

    steps.sort(key=lambda s: (-s.est_tests, s.object_type, s.flow))
    return steps


def render_plan(steps) -> str:
    L = ["CAPTURE PLAN (prioritised by authz tests unlocked):"]
    for i, s in enumerate(steps, 1):
        L.append(f"  {i}. [{s.est_tests:>3}] {s.flow}  | {s.accounts_needed} acc ({s.roles}) "
                 f"→ opens {s.unlocks}")
    return "\n".join(L) if steps else "CAPTURE PLAN: surface fully exercised (no gap)."
