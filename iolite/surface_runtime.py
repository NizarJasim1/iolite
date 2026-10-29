"""
surface_runtime — ingest the client's RUNTIME self-disclosure (Point 2, the
obfuscation-proof tier).

Heavy obfuscation defeats static mining, but not runtime: when the client executes
it CONSTRUCTS and SENDS concrete requests — a minified app still emits
`POST /api/v1/orders/123/refund` and a concrete GraphQL document on the wire. The
passive in-page hook (`assets/iolite_surface_hook.js`) records exactly what the
operator's OWN client emits during the operator's OWN legitimate session, and
writes a JSON log. This module folds that log into the surface at the HIGHEST
evidence tier (T1_LIVE) — the client already sent it, as the operator, in scope.

This is passive by the refined QL2 sense: the tool crafts NO request; it observes
only requests the operator's own client made for legitimate use. Deterministic (QL4).

Log record shape (all fields optional except method+url):
  {"method":"POST","url":"https://h/api/orders/123/refund","status":200,
   "gql":"mutation Refund($id:ID!){refund(id:$id){id}}","principal":"A"}
"""

from __future__ import annotations

import json
import re

from .models import (Endpoint, ObservedAccess, Provenance, SourceKind)
from .normalize import template_path, object_ids, endpoint_key
from . import gql_client, surface_ast
from .limits import MAX_INPUT_BYTES

_ID_SEG = re.compile(r"\{[^}/]+\}")


def _path_of(url: str) -> str:
    p = re.sub(r"^https?://[^/]+", "", url or "")
    return (p.split("?")[0].split("#")[0]) or "/"


def _records(data) -> list[dict]:
    """Accept a JSON string, a list of records, or {'calls':[...]} / HAR-lite."""
    if isinstance(data, str):
        try:
            data = json.loads(data[:MAX_INPUT_BYTES])
        except (ValueError, RecursionError):
            return []
    if isinstance(data, dict):
        data = data.get("calls") or data.get("records") or data.get("entries") or []
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def ingest_runtime(data, locator: str = "runtime") -> tuple[list[Endpoint], list[ObservedAccess]]:
    """Return (endpoints, accesses) recovered from a runtime hook log. Deterministic:
    endpoints sorted by key, accesses sorted by (principal, key, object)."""
    eps: dict[str, Endpoint] = {}
    accesses: list[ObservedAccess] = []
    for rec in _records(data):
        method = str(rec.get("method", "GET")).upper()
        url = str(rec.get("url", ""))
        gql = rec.get("gql") or rec.get("query")
        principal = rec.get("principal") or rec.get("pid")

        if gql and isinstance(gql, str):
            for ep in gql_client.extract_graphql_operations(gql, f"{locator}:gql"):
                if ep.key in eps:
                    eps[ep.key].merge(ep)
                else:
                    eps[ep.key] = ep
            continue

        if not url:
            continue
        path = template_path(_path_of(url))
        ids = object_ids(_path_of(url))
        prov = Provenance.of(SourceKind.HAR, f"{locator}:{method} {path}",
                             note="runtime self-disclosure (in-page hook)")
        ep = Endpoint(method=method, path=path,
                      effect=surface_ast._effect_for(method, _path_of(url)),
                      provenance=[prov], observed_ids=sorted(set(ids)))
        if ep.key in eps:
            eps[ep.key].merge(ep)
        else:
            eps[ep.key] = ep

        if principal and ids:
            oid = ids[0]
            accesses.append(ObservedAccess(
                principal_id=str(principal), endpoint_key=endpoint_key(method, path),
                object_id=str(oid), path=_path_of(url), method=method, provenance=prov,
                carrier="path", all_ids=[str(i) for i in ids],
                safe_read=(method == "GET")))

    ep_list = [eps[k] for k in sorted(eps)]
    accesses.sort(key=lambda a: (a.principal_id, a.endpoint_key, str(a.object_id)))
    return ep_list, accesses
