"""
metamorphic.py — the ONE sound oracle that DISPOSES (metamorphic differential).

Generators propose widely; this single gate decides. It is built on a metamorphic
relation (MR), not an absolute oracle — because for a hyperscale target no one can
enumerate the "correct" response, but everyone can state a RELATION that must hold
between two executions:

  MR_authz:  replay the SAME request as two principals. For a resource the attacker
             cannot legitimately reach, the two responses MUST DIFFER on the
             security-bearing, discriminating value. A VIOLATION is when the denied
             principal's response REPRODUCES the holder's private value — proven by
             value presence, never by a status code.

Soundness (zero-FP by construction) comes from composing the MR with four false-
positive filters drawn from the metamorphic-security-testing literature and from
IOLITE's own walls, and from resolving every uncertainty to ABSTAIN/LEAD — never a
claim:

  * surface-reachability   the attacker must NOT be legitimately authorized through
                           its OWN surface (else it is not a boundary at all).
  * privilege hierarchy    the attacker must not legitimately supervise the holder
                           (a supervisor seeing the object is benign).
  * error filtering        the holder's own (baseline) request must succeed and be
                           non-error, or the differential is meaningless.
  * stability + causal     the value must be STABLE across draws (flaky -> ABSTAIN),
                           independent controls must AGREE (observer-dependent ->
                           ABSTAIN), and a no-relationship CONTROL must be DENIED
                           (if a control also gets in, the relationship is not the
                           cause -> public-by-design, ABSTAIN).

Write safety (Wall-3): an irreversible write is REFUSED before it is ever performed;
a confirmed write must be net-zero restored or the run HALTs. The oracle therefore
never causes harm and never emits a false positive. Deterministic (QL4).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"   # sound, causal, stable, net-zero(if write) over-permission
    LEAD = "LEAD"             # plausible but not offline-provable -> hand to the live ONYX step
    ABSTAIN = "ABSTAIN"       # flaky / observer-dependent / benign-cause -> refuse to conclude
    REFUSED = "REFUSED"       # unsafe write -> refuse (no harm)
    CLEAN = "CLEAN"           # intent is actually enforced here (not a bug)


@dataclass
class Evidence:
    """What is known about one candidate. Offline, most fields come from the captured
    surface; live, they come from ONYX. Unknown -> conservative default -> LEAD/ABSTAIN."""
    # metamorphic differential
    holder_request_ok: bool = True            # baseline (holder's own request) is valid, non-error
    holder_has_discriminating_value: bool = True  # holder's response carries a private, discriminating value
    attacker_reproduced_value: bool | None = None # denied principal reproduced it (None = not yet observed)
    # false-positive filters
    attacker_surface_authorized: bool = False # attacker legitimately reaches this via its OWN surface
    attacker_is_supervisor: bool = False      # attacker legitimately supervises the holder
    stable: bool | None = True                # value stable across draws (None = flaky)
    controls_agree: bool = True               # >=2 no-relationship controls agree
    control_reproduced_value: bool = False    # a no-relationship control ALSO got in (benign cause)
    declared_private: bool = True             # the app's own privacy declaration anchors intent-deny
    # write safety (Wall-3)
    is_write: bool = False
    reversible: bool = True
    restored: bool = True


@dataclass
class OracleResult:
    verdict: str
    why: str
    cert: dict = field(default_factory=dict)


def decide(ev: Evidence, *, family: str = "", coord: tuple | None = None,
           derivation: str = "") -> OracleResult:
    """The single sound decision. Order matters: safety and benign-explanations are
    checked before any 'confirmed' can be reached; every uncertainty resolves away
    from a claim."""
    coord = coord or ()

    # 0) baseline must be valid (error filtering)
    if not ev.holder_request_ok:
        return OracleResult(Verdict.LEAD, "holder baseline request not established -> live confirm")

    # 1) the attacker must actually be OUTSIDE intent (else it is not a boundary)
    if ev.attacker_surface_authorized:
        return OracleResult(Verdict.CLEAN, "attacker legitimately reaches this via its own surface -> not an authz boundary")
    if ev.attacker_is_supervisor:
        return OracleResult(Verdict.CLEAN, "attacker legitimately supervises the holder -> benign hierarchy")
    if not ev.declared_private:
        return OracleResult(Verdict.ABSTAIN, "no declared-private / intent-deny anchor -> cannot establish a boundary")

    # 2) write safety FIRST — never perform or claim an irreversible write
    if ev.is_write and not ev.reversible:
        return OracleResult(Verdict.REFUSED, "irreversible write -> refused before execution (no harm)")

    # 3) the metamorphic differential (value presence, not status code)
    if not ev.holder_has_discriminating_value:
        return OracleResult(Verdict.LEAD, "no discriminating private value to difference on -> live confirm")
    if ev.attacker_reproduced_value is None:
        return OracleResult(Verdict.LEAD, "attacker response not observed offline -> hand to live ONYX Δstate")
    if not ev.attacker_reproduced_value:
        return OracleResult(Verdict.CLEAN, "attacker stably denied the private value -> intent enforced")

    # 4) attacker reproduced the private value -> run the FP filters
    if ev.stable is None:
        return OracleResult(Verdict.ABSTAIN, "value not stable across draws (flaky) -> abstain")
    if not ev.stable:
        return OracleResult(Verdict.CLEAN, "difference did not survive on a stable security-bearing field")
    if not ev.controls_agree:
        return OracleResult(Verdict.ABSTAIN, "independent controls disagree -> observer-dependent target -> abstain")
    if ev.control_reproduced_value:
        return OracleResult(Verdict.ABSTAIN, "a no-relationship control ALSO got in -> relationship is not the cause (public-by-design)")

    # 5) write must be net-zero
    if ev.is_write and not ev.restored:
        return OracleResult(Verdict.REFUSED, "write confirmed but not net-zero restored -> HALT")

    cert = {
        "family": family,
        "coord": list(coord),
        "proof": "denied principal reproduced the holder's private value (value-presence Δstate)",
        "causal": "no-relationship control was denied -> the authorization relationship is the cause",
        "stability": "value stable across draws; independent controls agree",
        "write_safe": (not ev.is_write) or (ev.reversible and ev.restored),
        "intent_derivation": derivation,
        "replayable": True,
    }
    return OracleResult(Verdict.CONFIRMED, "sound, causal, stable, net-zero over-permission", cert)


# --------------------------------------------------------------------------- #
# offline evidence from the captured surface (honest: proves only the chained  #
# case where the attacker already SAW the id; everything else -> a live LEAD)  #
# --------------------------------------------------------------------------- #

def evidence_from_model(model, cand) -> Evidence:
    """Derive what the CAPTURE already proves for a candidate. Offline IOLITE can
    only CONFIRM what the evidence it already holds entails (rare, e.g. a chained
    case where a denied principal demonstrably already saw the id). Everything else
    is a LEAD carrying the exact live probe — the honest floor (no fabricated FP)."""
    # does the attacker legitimately hold the object through its own access?
    holders = set()
    for oid in [cand.object_id]:
        if oid:
            holders |= set(model.holdings.get(str(oid), set()))
    attacker_authorized = cand.attacker in holders

    is_write = cand.action in ("write", "create", "delete")
    # Reversibility from the candidate's VERB semantics, not merely the literal "delete":
    # an RPC trigger like POST /transfer or /refund is a write="write" but IRREVERSIBLE,
    # so the crude `action != "delete"` rule would wrongly let the oracle perform it. Use
    # the carried Leap-1 safety tag (or derive it), and treat only reversible/compensating
    # actions as safe to confirm live; everything else is REFUSED before any packet.
    from .relation_model import action_safety
    safety = getattr(cand, "safety", "") or action_safety(
        cand.method, getattr(cand, "path", ""), getattr(cand, "field_name", ""))
    return Evidence(
        holder_request_ok=bool(cand.holder) or cand.family in ("workflow_state", "bopla_field"),
        holder_has_discriminating_value=bool(cand.object_id),
        # Honest floor: seeing/harvesting an id does NOT prove the private value was
        # reproduced — that needs the live request. So offline we never assert
        # reproduction (None -> LEAD). `seen_by_attacker` only raises the chained
        # candidate's confidence/priority, it is not proof.
        attacker_reproduced_value=None,
        attacker_surface_authorized=attacker_authorized,
        is_write=is_write,
        reversible=(safety in ("reversible", "compensating")),
        restored=True,
    )
