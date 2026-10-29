"""
reason · sequence — turn DECLARED workflow guards into state-indexed hypotheses for
ONYX to confirm by Δstate. The state/temporal axis the stateless differ lacks.

Three families, each mapped to a DECLARED guard (never to an observed-only deviation
— that is forbidden by ONYX RL1) and to an ONYX EffectClass ONYX already confirms:

  H1  workflow_gate_skip        (OWASP BLA2 CWOB / BLA6 MTV)  → STATE_GATE
        invoke a guarded operation from a pre-state where the declared gate is
        unsatisfied — on YOUR OWN object, whose pre-state YOU established legally.
        ONYX confirms only a PERSISTED, predecessor-unsatisfied Δstate.

  H2  workflow_state_conditional (BLA9 in-state / BLA3 OSM)  → STATE_GATE
        an operation guarded in one state, attempted in a state the guard forbids.

  H3  workflow_priv_transition   (BLA9 vertical, in-flow)    → AUTHORITY
        a privileged transition (approve/grant/refund/payout…) driven by a
        LOWER-privilege principal — discovered by flow position, not endpoint name.

Division of labour that resolves the "read-only vs must-write" tension ONYX names:
the OPERATOR establishes the pre-state on their OWN object during capture; ONYX
tests exactly one altered transition under attestation. No fabricated sequence, no
foreign object, no irreversible chain.

reason PROPOSES; ONYX DISPOSES (QL5). Own principals only (QL6). Deterministic (QL4).
Additive-only: empty guards ⇒ empty output ⇒ the engine is byte-identical to before.
"""

from __future__ import annotations

from ..models import Effect, SurfaceModel
from ..surface_model import privilege_scores
from .intent import AccessClass
from .enforcement import EnforcementView
from .differ import ReasonCandidate
from .workflow_intent import DeclaredGuard

_MUTATING = ("POST", "PUT", "PATCH", "DELETE", "MUTATION")
# operations whose transition is intrinsically privileged (someone senior does them)
_PRIV_VERBS = ("approve", "reject", "grant", "revoke", "refund", "payout", "settle",
               "publish", "escalate", "assign", "capture", "void", "release", "finalize",
               "finalise")
_MAX_ENDPOINTS_PER_GUARD = 4       # bound the fan-out (QL4)
_MAX_CANDIDATES = 200              # global bound


def _mutating_endpoints(model: SurfaceModel):
    for key in sorted(model.endpoints):
        ep = model.endpoints[key]
        if ep.method.upper() in _MUTATING:
            yield key, ep


def _borrow_object_id(model: SurfaceModel, object_hint: str) -> str:
    """A concrete id of the guarded object-type the OPERATOR legitimately holds
    (for a probeable request). Prefer an id observed at an endpoint whose path names
    the object type; else any held id. Deterministic."""
    oh = (object_hint or "").lower()
    if oh:
        for key in sorted(model.endpoints):
            if oh in key.lower():
                ids = model.endpoints[key].observed_ids
                if ids:
                    return sorted(ids)[0]
    for oid in sorted(model.holdings):
        return oid
    return ""


def _matches(key: str, ep, guard: DeclaredGuard) -> bool:
    kl = key.lower()
    verb_ok = bool(guard.operation_hint) and guard.operation_hint in kl
    obj_ok = bool(guard.object_hint) and guard.object_hint in kl
    if guard.operation_hint and guard.object_hint:
        return verb_ok or obj_ok
    return verb_ok or obj_ok            # at least one anchor must hit (see caller guard)


def _lowest_priv(model: SurfaceModel) -> list[str]:
    priv = privilege_scores(model)
    if not priv:
        return sorted(p.pid for p in model.principals)
    lo = min(priv.values())
    return sorted(pid for pid, s in priv.items() if s == lo)


def run_sequence(model: SurfaceModel, intent, enf: EnforcementView,
                 guards: list[DeclaredGuard]) -> list[ReasonCandidate]:
    """Generate state-indexed candidates from declared guards. Conservative: a guard
    with no anchor (no operation and no object hint) or no matching mutating endpoint
    produces nothing."""
    if not guards:
        return []
    own = sorted(p.pid for p in model.principals)
    low = _lowest_priv(model)
    out: list[ReasonCandidate] = []
    seen: set[tuple] = set()

    for guard in guards:
        if not guard.operation_hint and not guard.object_hint:
            continue                                    # unbindable — skip (no FP)
        matched = 0
        for key, ep in _mutating_endpoints(model):
            if matched >= _MAX_ENDPOINTS_PER_GUARD or len(out) >= _MAX_CANDIDATES:
                break
            if not _matches(key, ep, guard):
                continue
            matched += 1
            obj = _borrow_object_id(model, guard.object_hint)

            # --- pre-state + declared gate, from the guard's mode -----------------
            if guard.mode == "requires":
                pre_state = {guard.field: f"≠{guard.value}"}   # a state BEFORE the gate ran
                gate = f"{guard.field}=={guard.value}"
                why_state = (f"declared guard requires {guard.field}=={guard.value} "
                             f"before this operation; probe runs it from a pre-gate state")
            else:  # forbids
                pre_state = {guard.field: guard.value}         # the state the guard forbids
                gate = f"not({guard.field}=={guard.value})"
                why_state = (f"declared guard FORBIDS this operation while "
                             f"{guard.field}=={guard.value}; probe runs it in exactly that state")

            # --- H1 / H2: gate-skip / state-conditional (STATE_GATE) --------------
            sig1 = ("gate_skip", key, obj, guard.field, guard.value, guard.mode)
            if sig1 not in seen:
                seen.add(sig1)
                out.append(ReasonCandidate(
                    endpoint_key=key, method=ep.method, path=ep.path,
                    gap_kind="sequence_gate_skip",
                    intent_class=AccessClass.OWNER_ONLY.value,
                    intent_confidence=guard.confidence,
                    onyx_effect=Effect.STATE_GATE.value,
                    probe_pids=own, holder_pid="", object_id=obj, carrier="path",
                    family="workflow_gate_skip",
                    pre_state=pre_state, required_predecessor=gate,
                    rationale=(f"{why_state}; declared in {guard.source} "
                               f"({guard.confidence}); ONYX confirms only a PERSISTED, "
                               f"predecessor-unsatisfied Δstate on your own object. "
                               f"[{guard.evidence}]")))

            # --- H3: privileged transition usurpation (AUTHORITY) -----------------
            verb = guard.operation_hint
            if verb in _PRIV_VERBS and low and low != own:
                sig3 = ("priv_transition", key, obj, guard.field, guard.value)
                if sig3 not in seen:
                    seen.add(sig3)
                    out.append(ReasonCandidate(
                        endpoint_key=key, method=ep.method, path=ep.path,
                        gap_kind="sequence_priv_transition",
                        intent_class=AccessClass.ROLE_RESTRICTED.value,
                        intent_confidence=guard.confidence,
                        onyx_effect=Effect.AUTHORITY.value,
                        probe_pids=low, holder_pid="", object_id=obj, carrier="path",
                        family="workflow_priv_transition",
                        pre_state=pre_state, required_predecessor=gate,
                        rationale=(f"privileged transition '{verb}' is guarded by "
                                   f"{guard.gate_predicate}; a LOWER-privilege principal "
                                   f"attempts to drive it (discovered by flow position, "
                                   f"not endpoint name); ONYX confirms by Δstate")))

    out.sort(key=lambda c: (c.family, c.endpoint_key, c.object_id,
                            "".join(sorted(c.pre_state)) if c.pre_state else ""))
    return out
