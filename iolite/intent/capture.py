"""
capture.py — the EVIDENCE record the deep layer reasons over, and how to derive it.

v1.15 reasoned over endpoints + holdings only; it never looked at what the server
actually RETURNED, so it could never prove anything offline and its field/state
detection was a hardcoded wordlist. v1.16 introduces one richer, honest unit of
evidence — a `CapturedExchange` — that carries BOTH what the client sent and what the
server returned for one request, by one of the operator's own principals. Everything
that makes the tool actually confirm bugs offline (corroborate.py), learn the target's
own schema instead of guessing (schema_learn.py), and track id disclosure for real
chained reachability (relation graph) is built on this record.

A `CapturedExchange` is produced from a real multi-principal HAR (request + response),
which IOLITE already ingests. When only a thin SurfaceModel is available (no responses),
`exchanges_from_model` degrades honestly: response_fields is empty, so nothing is
corroborated offline — it becomes a live lead, never a fabricated confirmation.

Pure-stdlib, deterministic (QL4). Own principals only (QL6).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CapturedExchange:
    """One request/response by one operator-controlled principal. The atom of evidence."""
    principal: str
    endpoint_key: str                 # METHOD /templated/path
    method: str
    object_id: str                    # the primary object this addressed ("" if none)
    owned: bool                       # did THIS principal create/own the object (vs merely access it)
    request_fields: dict = field(default_factory=dict)   # name -> value the CLIENT sent
    response_fields: dict = field(default_factory=dict)  # name -> scalar value the SERVER returned
    response_ids: list = field(default_factory=list)      # object ids disclosed in the response (for chaining)
    status: int = 200
    tenant: str = ""
    seq: int = 0                      # observation order (time proxy, for state transitions)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def mutating(self) -> bool:
        return self.method.upper() in ("POST", "PUT", "PATCH", "DELETE")


def _scalars(body):
    """Flatten a body/response dict one level + one nested level into name->scalar."""
    out = {}
    if isinstance(body, dict):
        for k, v in body.items():
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    if not isinstance(v2, (dict, list)):
                        out[str(k2)] = v2
            elif isinstance(v, list):
                continue
            else:
                out[str(k)] = v
    return out


def exchanges_from_model(model) -> list[CapturedExchange]:
    """Best-effort exchanges from a SurfaceModel. Honest degradation: the base model has
    no responses, so response_fields stays empty (=> corroboration abstains, leads only).
    `owned` is inferred from the partition: a principal OWNS an object only if it is the
    SOLE holder of it (disjoint partition = creator); shared holders => merely accessed."""
    out = []
    for i, acc in enumerate(sorted(model.accesses,
                                   key=lambda a: (a.endpoint_key, str(a.object_id), a.principal_id))):
        oid = str(acc.object_id)
        holders = model.holdings.get(oid, set())
        owned = (holders == {acc.principal_id})      # sole holder => creator/owner
        req = _scalars(acc.body)
        tenant = ""
        for k, v in req.items():
            if k.lower() in ("tenant_id", "org_id", "organization_id", "workspace_id") and v:
                tenant = str(v)
        out.append(CapturedExchange(
            principal=acc.principal_id, endpoint_key=acc.endpoint_key, method=acc.method,
            object_id=oid, owned=owned, request_fields=req, response_fields={},
            response_ids=[str(x) for x in (acc.all_ids or []) if str(x) != oid],
            status=200, tenant=tenant, seq=i))
    return out


def merge_exchanges(model_exchanges, har_exchanges) -> list[CapturedExchange]:
    """Prefer response-bearing (HAR) exchanges; fall back to model-derived ones for
    endpoints the HAR did not cover. Deterministic."""
    by_key = {}
    for e in list(model_exchanges) + list(har_exchanges):
        k = (e.principal, e.endpoint_key, e.object_id)
        cur = by_key.get(k)
        if cur is None or (not cur.response_fields and e.response_fields):
            by_key[k] = e
    return [by_key[k] for k in sorted(by_key, key=lambda t: (t[1], t[2], t[0]))]
