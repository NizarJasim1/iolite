"""
divergence.py — the WIDE divergence enumerator (generators that PROPOSE).

Given the relational intent lattice, enumerate every (attacker, action, object,
field, state) tuple that is (a) REACHABLE from the acquired surface and (b) one the
intent lattice DENIES — i.e. a place the implementation would be wrong to allow.
Each candidate carries the intended-DENY derivation as its proof obligation.

This is where IOLITE stops looking for known vuln *shapes* and starts looking for
intent/implementation DIVERGENCE across the dimensions that survive on mature
targets. The six families map 1:1 to the empirical bug-bounty BOLA taxonomy (what
actually pays), and five of the six are the documented automated-scanner blind spots:

  read_bola       direct cross-user read            (36.9% — the one scanners DO catch)
  action_bola     write / delete / trigger cross-user (41.7% — scanners miss ~46%)   *blind*
  bopla_field     owner sets a server-authoritative field (role/price/status)        *blind*
  rebinding       client-supplied ownership field reassigns the object               *blind*
  workflow_state  action allowed in a terminal lifecycle state (archived/revoked)    *blind*
  chained         id harvested at one endpoint, used at another with no check        *blind*
  tenant          cross-tenant / cross-namespace access                              *blind*
  vertical        lower-privilege principal reaches a function-level action (BFLA)

Generators only PROPOSE (QL5). Widening the generators RAISES recall and — because a
single sound oracle DISPOSES downstream — can never raise the false-positive rate.
Own principals only (QL6). Deterministic (QL4).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import SurfaceModel
from .relation_model import (Action, Decision, Lattice, action_of_method,
                             build_lattice, post_is_action, resource_type_of, action_safety)

# EV priors (for SCHEDULING only — never a claim). Grounded in the taxonomy:
# deletion is high-impact/often irreversible; cross-tenant & BFLA are critical;
# action-level carries disproportionate severity vs. read.
_EV = {
    "read_bola":      (1500, "high"),
    "action_bola":    (2500, "high"),
    "bopla_field":    (2000, "high"),
    "rebinding":      (2600, "critical"),
    "workflow_state": (1800, "high"),
    "chained":        (2200, "high"),
    "tenant":         (3500, "critical"),
    "vertical":       (2800, "critical"),
}
_DELETE_BONUS = 600  # deletion is higher-impact (often irreversible)


@dataclass
class DivergenceCandidate:
    """A hypothesis: intent DENIES this, so if the implementation ALLOWS it, it is a
    finding. No verdict here — the metamorphic oracle decides."""
    family: str
    attacker: str                 # the operator's own principal intent says to deny
    action: str                   # read | create | write | delete
    endpoint_key: str
    method: str
    path: str                     # concrete, probeable (id substituted) where possible
    object_id: str = ""
    holder: str = ""              # who legitimately holds it ("" if none/declared)
    field_name: str = ""
    field_value: object = None
    state: str = ""
    derivation: str = ""          # WHY intent denies this (the proof obligation)
    query: dict = field(default_factory=dict)
    body: object = None
    severity: str = "medium"
    payout: int = 0
    reachable: bool = True        # a concrete request exists to reproduce
    chain_from: str = ""          # for chained: the endpoint the id was harvested at
    safety: str = "reversible"    # reversibility of a mutating action (Leap-1 safety tag):
                                  # reversible | compensating | irreversible | unknown —
                                  # consumed by the oracle (refuse irreversible) & scheduler

    @property
    def key(self) -> tuple:
        return (self.family, self.method, self.path, str(self.object_id),
                self.field_name, self.attacker)

    @property
    def equiv_class(self) -> tuple:
        """Authorization-equivalence class for quotient reduction: same family, same
        object-TYPE+action+field — one representative stands for N concrete instances."""
        return (self.family, self.action, self.field_name,
                _type_token(self.path))


def _type_token(path: str) -> str:
    from .relation_model import _obj_type_of_path
    return _obj_type_of_path(path)


def _others_denied(lat: Lattice, action: Action, *, endpoint_key: str, oid: str,
                   holder: str, field_name: str = "", field_value=None,
                   state: str = "") -> list[tuple[str, str]]:
    """Every principal (other than the holder) that intent DENIES for this tuple,
    with the derivation. UNKNOWN is skipped (honest floor -> counted elsewhere)."""
    out = []
    for pid in lat.all_pids:
        if pid == holder:
            continue
        dec, why = lat.intended_decision(
            pid, action, endpoint_key=endpoint_key, oid=oid,
            field_name=field_name, field_value=field_value, state=state)
        if dec == Decision.DENY:
            out.append((pid, why))
    return out


def _mutating_template(lat: Lattice, otype: str, method: str) -> str:
    """A concrete-ish endpoint path template of `otype` served under `method` (so an
    action-BOLA probe addresses the right surface). Empty if the type has no such verb."""
    if otype not in lat.types:
        return ""
    for key in sorted(lat.types[otype].endpoints):
        m, _, p = key.partition(" ")
        if m.upper() == method.upper():
            return p
    return ""


def _fill(path: str, oid: str) -> str:
    import re
    if oid and re.search(r"\{[^}/]+\}", path):
        return re.sub(r"\{[^}/]+\}", str(oid), path, count=1)
    return path


def enumerate_divergences(model: SurfaceModel, lat: Lattice | None = None,
                          *, rich: bool = True) -> list[DivergenceCandidate]:
    """Produce the full wide candidate set. Deterministic ordering."""
    lat = lat or build_lattice(model, rich=rich)
    out: list[DivergenceCandidate] = []
    seen: set = set()

    def emit(c: DivergenceCandidate):
        if c.key in seen:
            return
        seen.add(c.key)
        base, sev = _EV[c.family]
        c.payout = base + (_DELETE_BONUS if c.action == Action.DELETE.value else 0)
        c.severity = sev if c.action != Action.DELETE.value else "critical"
        # Leap-1 safety tag: classify the action's reversibility from its verb semantics
        # (reads and field-writes restore; money/destroy/grant do not). Fail-closed.
        c.safety = ("reversible" if c.action == Action.READ.value
                    else action_safety(c.method, c.path, c.field_name))
        out.append(c)

    # index: which concrete ids each principal has already SEEN (for chained harvest)
    seen_ids_by_pid: dict = {}
    for acc in model.accesses:
        for oid in (acc.all_ids or [acc.object_id]):
            if oid:
                seen_ids_by_pid.setdefault(acc.principal_id, set()).add(str(oid))

    # index: action/trigger POST endpoints (a WRITE on an EXISTING object:
    # …/{id}/refund, …/{id}/promote) by the resource TYPE they act on — verb/id-aware,
    # so POST /orders/{id}/cancel is an action on 'order', never a create of a 'cancel'
    # collection. Create-collection POSTs are deliberately excluded (no foreign object)
    # and remain the domain of the BOPLA/rebinding field families below. This is the
    # missing half of the "trigger cross-user" action-BOLA family (the generator walked
    # PATCH/PUT/DELETE only; POST triggers were invisible). QL5 keeps it sound: a
    # mis-included action only adds a candidate the oracle discards — never a finding.
    action_posts_by_type: dict = {}
    for _ep in model.endpoints.values():
        if _ep.method.upper() != "POST" or not post_is_action(_ep.path):
            continue
        action_posts_by_type.setdefault(resource_type_of(_ep.path), []).append(_ep.path)
    for _t in action_posts_by_type:
        action_posts_by_type[_t] = sorted(set(action_posts_by_type[_t]))

    # ---- walk every observed legitimate access = a reproducible request -------
    for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, str(a.object_id))):
        otype = lat.type_of_endpoint(acc.endpoint_key)
        oid = str(acc.object_id)
        of = lat.objects.get(oid)
        state = of.state if of else ""

        # (1) READ-BOLA — the classic (kept for completeness/coverage)
        if acc.safe_read:
            for pid, why in _others_denied(lat, Action.READ, endpoint_key=acc.endpoint_key,
                                           oid=oid, holder=acc.principal_id, state=state):
                emit(DivergenceCandidate(
                    family="read_bola", attacker=pid, action=Action.READ.value,
                    endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                    object_id=oid, holder=acc.principal_id, derivation=why,
                    query=dict(acc.query or {}), body=acc.body))

                # (7) CHAINED — this denied principal has ALREADY seen the id elsewhere
                # (harvested it from another endpoint's response) -> two-step reach.
                if oid in seen_ids_by_pid.get(pid, set()):
                    emit(DivergenceCandidate(
                        family="chained", attacker=pid, action=Action.READ.value,
                        endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                        object_id=oid, holder=acc.principal_id,
                        derivation=(f"{pid} harvested id {oid} at another endpoint, then reaches "
                                    f"{acc.endpoint_key} which enforces no ownership check: " + why),
                        query=dict(acc.query or {}), body=acc.body,
                        chain_from="(harvested from a prior response)"))

        # (2) ACTION-BOLA — write / delete / trigger cross-user (the 41.7% family)
        for method in ("PATCH", "PUT", "DELETE"):
            if otype in lat.types and method in lat.types[otype].methods:
                act = action_of_method(method)
                tmpl = _mutating_template(lat, otype, method) or acc.path
                path = _fill(tmpl, oid)
                ekey = f"{method} {tmpl}" if tmpl else acc.endpoint_key
                for pid, why in _others_denied(lat, act, endpoint_key=ekey,
                                               oid=oid, holder=acc.principal_id, state=state):
                    emit(DivergenceCandidate(
                        family="action_bola", attacker=pid, action=act.value,
                        endpoint_key=ekey, method=method, path=path,
                        object_id=oid, holder=acc.principal_id, derivation=why))

        # (2b) ACTION-BOLA via POST — an RPC action/trigger on the SAME existing object
        # (…/{id}/refund, …/{id}/promote). Classified behaviourally as a cross-user WRITE,
        # not a collection create. This is the action-BOLA surface the PATCH/PUT/DELETE
        # walk could not see, and the larger half of the "trigger" taxonomy on mature APIs.
        for tmpl in action_posts_by_type.get(otype, ()):
            for pid, why in _others_denied(lat, Action.WRITE, endpoint_key=f"POST {tmpl}",
                                           oid=oid, holder=acc.principal_id, state=state):
                emit(DivergenceCandidate(
                    family="action_bola", attacker=pid, action=Action.WRITE.value,
                    endpoint_key=f"POST {tmpl}", method="POST", path=_fill(tmpl, oid),
                    object_id=oid, holder=acc.principal_id,
                    derivation="RPC action/trigger on an existing object — " + why))

        # (5) WORKFLOW-STATE — a mutating action while the object is in a terminal state
        # (terminal = hardcoded prior OR LEARNED from the transition graph, any language)
        if state and lat._is_excluded(state):
            for method in ("PATCH", "PUT", "DELETE", "POST"):
                if otype in lat.types and method in lat.types[otype].methods:
                    act = action_of_method(method)
                    tmpl = _mutating_template(lat, otype, method) or acc.path
                    # even the HOLDER should be denied here -> every principal is a probe
                    for pid in lat.all_pids:
                        dec, why = lat.intended_decision(
                            pid, act, endpoint_key=f"{method} {tmpl}", oid=oid, state=state)
                        if dec == Decision.DENY:
                            emit(DivergenceCandidate(
                                family="workflow_state", attacker=pid, action=act.value,
                                endpoint_key=f"{method} {tmpl}", method=method,
                                path=_fill(tmpl, oid), object_id=oid, holder=acc.principal_id,
                                state=state, derivation=why))

        # (6) TENANT — a principal of another tenant reaches a tenant-scoped object
        if of and of.tenant:
            for pid in lat.all_pids:
                if lat.principal_tenant.get(pid, "") == of.tenant:
                    continue
                dec, why = lat.intended_decision(
                    pid, Action.READ, endpoint_key=acc.endpoint_key, oid=oid, state=state)
                if dec == Decision.DENY and "tenant" in why.lower():
                    emit(DivergenceCandidate(
                        family="tenant", attacker=pid, action=Action.READ.value,
                        endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                        object_id=oid, holder=acc.principal_id, derivation=why,
                        query=dict(acc.query or {}), body=acc.body))

    # ---- field families: BOPLA + rebinding (per object-type with a write surface) --
    for otype, tf in sorted(lat.types.items()):
        write_methods = [m for m in ("PATCH", "PUT", "POST") if m in tf.methods]
        if not write_methods:
            continue
        method = write_methods[0]
        tmpl = _mutating_template(lat, otype, method)
        if not tmpl:
            continue
        # a concrete object of this type to address (any observed one)
        oid = next((o.oid for o in lat.objects.values() if o.otype == otype and o.holders), "")
        holder = ""
        if oid and oid in lat.objects:
            holder = next(iter(sorted(lat.objects[oid].holders)), "")
        for fname, fclass in sorted(tf.fields.items()):
            if fclass == "server_auth":
                # (3) BOPLA — even the OWNER must not set a server-authoritative field
                probe = holder or (lat.all_pids[0] if lat.all_pids else "")
                if not probe:
                    continue
                dec, why = lat.intended_decision(
                    probe, action_of_method(method), endpoint_key=f"{method} {tmpl}",
                    oid=oid, field_name=fname)
                if dec == Decision.DENY:
                    emit(DivergenceCandidate(
                        family="bopla_field", attacker=probe, action=action_of_method(method).value,
                        endpoint_key=f"{method} {tmpl}", method=method, path=_fill(tmpl, oid),
                        object_id=oid, holder=holder, field_name=fname,
                        field_value="<elevated>", derivation=why,
                        body={fname: "<elevated>"}))
            elif fclass == "ownership":
                # (4) REBINDING — set the ownership field to ANOTHER principal
                probe = holder or (lat.all_pids[0] if lat.all_pids else "")
                other = next((p for p in lat.all_pids if p != probe), "")
                if not probe or not other:
                    continue
                dec, why = lat.intended_decision(
                    probe, action_of_method(method), endpoint_key=f"{method} {tmpl}",
                    oid=oid, field_name=fname, field_value=other)
                if dec == Decision.DENY:
                    emit(DivergenceCandidate(
                        family="rebinding", attacker=probe, action=action_of_method(method).value,
                        endpoint_key=f"{method} {tmpl}", method=method, path=_fill(tmpl, oid),
                        object_id=oid, holder=holder, field_name=fname, field_value=other,
                        derivation=why, body={fname: other}))

    # ---- (8) VERTICAL / BFLA — the measured privilege lattice, GLOBAL + per-type.
    # The global scalar catches a plainly lower-privilege principal; the typed pass adds
    # the DOMAIN-scoped BFLA a flat score hides (an attacker high overall but with no
    # authority in THIS resource type). Raise-only; emit() dedups the overlap.
    from ..surface_model import vertical_candidates
    from .relation_model import vertical_candidates_typed
    for vc in list(vertical_candidates(model)) + list(vertical_candidates_typed(model)):
        why = (f"privilege-guarded endpoint reached by {vc.holder_pid}; lower-privilege "
               f"principals must be denied (BFLA / API5:2023)")
        for pid in vc.probe_pids:
            emit(DivergenceCandidate(
                family="vertical", attacker=pid, action=action_of_method(vc.method).value,
                endpoint_key=vc.endpoint_key, method=vc.method, path=vc.path,
                object_id=str(vc.object_id), holder=vc.holder_pid, derivation=why,
                query=dict(vc.query or {}), body=vc.body))

    out.sort(key=lambda c: (c.family, c.path, str(c.object_id), c.field_name, c.attacker))
    return out


def family_counts(cands: list[DivergenceCandidate]) -> dict:
    d: dict = {}
    for c in cands:
        d[c.family] = d.get(c.family, 0) + 1
    return dict(sorted(d.items()))
