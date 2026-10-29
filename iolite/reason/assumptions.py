"""
reason · assumptions — HAZOP for authorization. Every authz system rests on unstated
developer assumptions; the deepest bugs are assumptions nobody thought to question.
We keep a library and, per target, systematically NEGATE each one → a candidate
ONYX confirms by Δstate.

All active detectors are bounded & non-destructive (P3): reads / a single altered
read, as your own principals, in scope. reason PROPOSES; ONYX DISPOSES (QL5).
Own principals only (QL6). Deterministic (QL4). Each maps to an ONYX EffectClass.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Effect, SurfaceModel
from ..idformat import classify
from ..normalize import object_ids as path_object_ids
from ..surface_model import privilege_scores
from .intent import IntentRule
from .enforcement import EnforcementView
from .differ import ReasonCandidate

# --- signal vocabularies (path/param markers) ------------------------------- #
_INTERNAL_MARKERS = ("/internal", "/debug", "/private", "/actuator", "/_debug",
                     "/trace", "/backend", "/sys/", "/ops/")
_ROLE_KEYS = ("role", "roles", "is_admin", "isadmin", "admin", "is_staff",
              "permission", "permissions", "scope", "access_level", "level",
              "user_type", "account_type", "priv")
_STATE_KEYS = ("status", "state", "visibility", "archived", "active", "deleted",
               "is_active", "is_deleted", "stage", "phase")
_HIDDEN_STATES = ("deleted", "archived", "removed", "disabled")
_EXPORT_MARKERS = ("export", "download", "/report", "backup", "dump", ".csv",
                   ".pdf", ".xlsx", "/csv", "/pdf")


def _lowest_priv(model: SurfaceModel) -> list[str]:
    priv = privilege_scores(model)
    if not priv:
        return sorted(p.pid for p in model.principals)
    lo = min(priv.values())
    return sorted(pid for pid, s in priv.items() if s == lo)


@dataclass
class Assumption:
    name: str
    statement: str          # the belief the developer never questioned
    status: str             # "active" | "planned"

    def candidates(self, model: SurfaceModel, intent: dict[str, IntentRule],
                   enf: EnforcementView) -> list[ReasonCandidate]:
        return []


# --------------------------------------------------------------------------- #
# 1. ids are unguessable  → adjacent-id read (IDOR by enumeration)             #
# --------------------------------------------------------------------------- #
class UnguessableIds(Assumption):
    def __init__(self):
        super().__init__("ids_unguessable",
                         "object identifiers are unguessable, so no ownership check is needed",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, str(a.object_id))):
            if not acc.safe_read or not acc.object_id:
                continue
            kind, why = classify(str(acc.object_id))
            if kind not in ("sequential", "numeric"):
                continue
            try:
                neighbor = str(int(str(acc.object_id)) + 1)
            except ValueError:
                continue
            if neighbor in (acc.all_ids or [acc.object_id]):
                continue
            npath = acc.path.replace(str(acc.object_id), neighbor, 1)
            if npath == acc.path or (acc.endpoint_key, neighbor) in seen:
                continue
            seen.add((acc.endpoint_key, neighbor))
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=npath,
                gap_kind="assumption_ids_unguessable", intent_class="OWNER_ONLY",
                intent_confidence="medium", onyx_effect=Effect.OBJECT_ACCESS.value,
                probe_pids=[acc.principal_id], holder_pid=acc.principal_id,
                object_id=neighbor, carrier=acc.carrier, family="assumption_enum",
                query=dict(acc.query or {}), body=acc.body,
                rationale=(f"id '{acc.object_id}' is {kind} ({why}); {acc.principal_id} requests "
                           f"adjacent id {neighbor} it does not own — ONYX confirms by Δstate")))
        return out


# --------------------------------------------------------------------------- #
# 2. internal-only endpoints are unreachable → reach them as a normal user     #
# --------------------------------------------------------------------------- #
class InternalOnly(Assumption):
    def __init__(self):
        super().__init__("endpoint_internal_only",
                         "this endpoint is internal-only, so a client will never call it directly",
                         "active")

    def candidates(self, model, intent, enf):
        attackers = _lowest_priv(model)
        if not attackers:
            return []
        out = []
        for ep in model.sorted_endpoints():
            low = ep.path.lower()
            if not any(mark in low for mark in _INTERNAL_MARKERS):
                continue
            obs = enf.per_endpoint.get(ep.key)
            if obs is not None and obs.reached:        # already reached → not hidden
                continue
            path = ep.path
            obj = ""
            if "{" in path:                            # need a concrete id to be probeable
                borrow = ep.observed_ids[0] if ep.observed_ids else next(iter(sorted(enf.holdings)), "")
                if not borrow:
                    continue
                import re
                path = re.sub(r"\{[^}/]+\}", borrow, path, count=1)
                obj = borrow
            eff = ep.effect.value if ep.effect != Effect.NONE else Effect.OBJECT_ACCESS.value
            out.append(ReasonCandidate(
                endpoint_key=ep.key, method=ep.method, path=path,
                gap_kind="assumption_internal_only", intent_class="ADMIN_ONLY",
                intent_confidence="medium", onyx_effect=eff, probe_pids=list(attackers),
                holder_pid="", object_id=obj, carrier="path", family="assumption_internal",
                rationale=("path is marked internal/debug/private but is network-reachable; "
                           "lowest-privilege principal attempts it — ONYX confirms by Δstate")))
        return out


# --------------------------------------------------------------------------- #
# 3. the client always sends the true role → elevate the client-supplied role  #
# --------------------------------------------------------------------------- #
class ClientSendsTrueRole(Assumption):
    def __init__(self):
        super().__init__("client_sends_true_role",
                         "the client always sends the correct role/permission",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            q = dict(acc.query or {})
            hit = next((k for k in q if k.lower() in _ROLE_KEYS), None)
            if not hit or str(q[hit]).lower() == "admin":
                continue
            sig = (acc.endpoint_key, hit)
            if sig in seen:
                continue
            seen.add(sig)
            q2 = dict(q); q2[hit] = "admin"
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                gap_kind="assumption_client_role", intent_class="ADMIN_ONLY",
                intent_confidence="medium", onyx_effect=Effect.AUTHORITY.value,
                probe_pids=[acc.principal_id], holder_pid=acc.principal_id,
                object_id=str(acc.object_id or ""), carrier="query",
                family="assumption_client_role", query=q2, body=acc.body,
                rationale=(f"role carried in client-controlled '{hit}'; {acc.principal_id} resends "
                           f"with {hit}=admin — if honored the client is trusted for authorization "
                           f"(BFLA); ONYX confirms by Δstate")))
        return out


# --------------------------------------------------------------------------- #
# 4. deleted/archived objects stay inaccessible → request the hidden state      #
# --------------------------------------------------------------------------- #
class DeletedStaysInaccessible(Assumption):
    def __init__(self):
        super().__init__("deleted_stays_inaccessible",
                         "a deleted/archived object stays inaccessible (no re-check on lifecycle)",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            q = dict(acc.query or {})
            hit = next((k for k in q if k.lower() in _STATE_KEYS), None)
            if not hit or str(q[hit]).lower() in _HIDDEN_STATES:
                continue
            sig = (acc.endpoint_key, hit)
            if sig in seen:
                continue
            seen.add(sig)
            q2 = dict(q); q2[hit] = "deleted"
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                gap_kind="assumption_deleted_accessible", intent_class="OWNER_ONLY",
                intent_confidence="low", onyx_effect=Effect.STATE_GATE.value,
                probe_pids=[acc.principal_id], holder_pid=acc.principal_id,
                object_id=str(acc.object_id or ""), carrier="query",
                family="assumption_lifecycle", query=q2, body=acc.body,
                rationale=(f"lifecycle carried in '{hit}'; {acc.principal_id} flips it to 'deleted' — "
                           f"authz may not be re-evaluated on a hidden-state object; ONYX confirms by Δstate")))
        return out


# --------------------------------------------------------------------------- #
# 5. a child re-inherits parent authz → own the parent, swap the child id       #
# --------------------------------------------------------------------------- #
class ChildReinheritsAuthz(Assumption):
    def __init__(self):
        super().__init__("child_reinherits_authz",
                         "a nested/child resource re-checks authorization like its parent",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            ids = path_object_ids(acc.path)            # concrete id segments, in order
            if len(ids) < 2:
                continue
            child = ids[-1]
            try:
                neighbor = str(int(child) + 1)
            except ValueError:
                continue
            # replace only the LAST id occurrence (the child), keep the parent (owned)
            head, _sep, tail = acc.path.rpartition(child)
            if not head:
                continue
            npath = head + neighbor + tail
            sig = (acc.endpoint_key, npath)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=npath,
                gap_kind="assumption_nested_child", intent_class="OWNER_ONLY",
                intent_confidence="medium", onyx_effect=Effect.OBJECT_ACCESS.value,
                probe_pids=[acc.principal_id], holder_pid=acc.principal_id,
                object_id=neighbor, carrier="path", family="assumption_nested_child",
                query=dict(acc.query or {}), body=acc.body,
                rationale=(f"nested path: parent kept (owned), child id {child}→{neighbor} swapped; "
                           f"child authz may not be re-checked (second-order IDOR); ONYX confirms by Δstate")))
        return out


# --------------------------------------------------------------------------- #
# 6. an export inherits the query's authz → reach the export as another peer    #
# --------------------------------------------------------------------------- #
class ExportInheritsQueryAuthz(Assumption):
    def __init__(self):
        super().__init__("export_inherits_query_authz",
                         "an export/report inherits the authorization of the query that built it",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            low = (acc.path + " " + acc.endpoint_key).lower()
            if not any(mark in low for mark in _EXPORT_MARKERS):
                continue
            ids = acc.all_ids or ([acc.object_id] if acc.object_id else [])
            holders = set().union(*(enf.holders_of(i) for i in ids)) if ids else set()
            others = [p for p in enf.all_principals if p not in holders and p != acc.principal_id]
            if not others:
                continue
            sig = (acc.endpoint_key, acc.path)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                gap_kind="assumption_export", intent_class="OWNER_ONLY",
                intent_confidence="medium", onyx_effect=Effect.CROSS_SURFACE.value,
                probe_pids=sorted(others), holder_pid=acc.principal_id,
                object_id=str(acc.object_id or ""), carrier=acc.carrier,
                family="assumption_export", query=dict(acc.query or {}), body=acc.body,
                rationale=("export/report/download surface; a peer principal requests the same export — "
                           "the export may not re-apply the query's authorization; ONYX confirms by Δstate")))
        return out


class WebhookOriginTrusted(Assumption):
    """Negate 'a webhook/callback request is from us': webhook config/history often
    exposes the signing secret. A peer reading another principal's webhook resource
    is a high-value BOLA (secret disclosure → forgeable origin)."""

    def __init__(self):
        super().__init__("webhook_origin_trusted",
                         "a webhook/callback is trusted as coming from us (secret not peer-readable)",
                         "active")

    def candidates(self, model, intent, enf):
        out, seen = [], set()
        markers = ("webhook", "callback", "/hook", "notify", "/events", "/ipn", "/incoming")
        for acc in sorted(model.accesses, key=lambda a: (a.endpoint_key, a.path)):
            if not acc.safe_read:
                continue
            low = (acc.path + " " + acc.endpoint_key).lower()
            if not any(m in low for m in markers):
                continue
            ids = acc.all_ids or ([acc.object_id] if acc.object_id else [])
            holders = set().union(*(enf.holders_of(i) for i in ids)) if ids else set()
            others = [p for p in enf.all_principals if p not in holders and p != acc.principal_id]
            if not others or (acc.endpoint_key, acc.path) in seen:
                continue
            seen.add((acc.endpoint_key, acc.path))
            out.append(ReasonCandidate(
                endpoint_key=acc.endpoint_key, method=acc.method, path=acc.path,
                gap_kind="assumption_webhook", intent_class="OWNER_ONLY",
                intent_confidence="medium", onyx_effect=Effect.FIELD_PROJECTION.value,
                probe_pids=sorted(others), holder_pid=acc.principal_id,
                object_id=str(acc.object_id or ""), carrier=acc.carrier,
                family="assumption_webhook", query=dict(acc.query or {}), body=acc.body,
                rationale=("webhook/callback resource; a peer principal reads it — webhook config "
                           "often leaks the signing secret (forgeable origin); ONYX confirms by Δstate")))
        return out


CATALOG: list[Assumption] = [
    UnguessableIds(),
    InternalOnly(),
    ClientSendsTrueRole(),
    DeletedStaysInaccessible(),
    ChildReinheritsAuthz(),
    ExportInheritsQueryAuthz(),
    WebhookOriginTrusted(),
]


def run_assumptions(model: SurfaceModel, intent, enf) -> list[ReasonCandidate]:
    out: list[ReasonCandidate] = []
    for a in CATALOG:
        if a.status == "active":
            out.extend(a.candidates(model, intent, enf))
    return out


def catalog_status() -> list[dict]:
    return [{"name": a.name, "assumption": a.statement, "status": a.status}
            for a in CATALOG]
