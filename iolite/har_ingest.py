"""
② Session bridge — HAR (your authenticated capture) → per-principal surface.

Each HAR is one account's legitimate browsing (the principal axis). v0.3
mines object ids from EVERY carrier (path, query, identity header, JWT claim,
GraphQL variable, body field) via `carriers.py`, so query-keyed and GraphQL IDORs
are captured, not just path-keyed ones. A GET that addresses ANY object id becomes
OBJECT_ACCESS even when the path has no {id} segment — otherwise ONYX would skip it.

No requests are sent — this reads a file you already captured (QL2). Out-of-scope
hosts are dropped by the Scope-Guard (QL1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit, parse_qs

from . import carriers
from .models import (Effect, Endpoint, ObservedAccess, Principal, Provenance,
                     SourceKind)
from .normalize import endpoint_key, template_path, split_host_path
from .scope_guard import ScopeGuard
from .limits import MAX_HAR_ENTRIES, MAX_BODY_BYTES

_SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token",
                   "x-csrf-token", "x-xsrf-token"}
_PROFILE_HEADERS = {"user-agent", "accept", "accept-language", "accept-encoding",
                    "referer", "origin", "sec-ch-ua", "sec-ch-ua-mobile",
                    "sec-ch-ua-platform", "sec-fetch-site", "sec-fetch-mode",
                    "sec-fetch-dest", "content-type"}


@dataclass
class HarResult:
    principal: Principal
    endpoints: list[Endpoint] = field(default_factory=list)
    accesses: list[ObservedAccess] = field(default_factory=list)
    hosts: dict[str, int] = field(default_factory=dict)
    skipped_hosts: dict[str, int] = field(default_factory=dict)


def _headers_map(header_list) -> dict[str, str]:
    out = {}
    for h in header_list or []:
        if isinstance(h, dict) and "name" in h:
            out[str(h["name"]).lower()] = str(h.get("value", ""))
    return out


def _query_map(url: str) -> dict:
    q = parse_qs(urlsplit(url).query, keep_blank_values=True)
    # collapse single-value lists for readability; keep lists when repeated
    return {k: (v[0] if len(v) == 1 else v) for k, v in q.items()}


def _body(req: dict):
    pd = (req or {}).get("postData") or {}
    text = pd.get("text")
    if not text or not isinstance(text, str) or len(text) > MAX_BODY_BYTES:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _is_graphql_read(path: str, body) -> bool:
    """A GraphQL POST that is a QUERY (read), not a mutation/subscription — safe to
    reproduce cross-principal like a GET."""
    if "graphql" not in path.lower() and "gql" not in path.lower():
        return False
    if not isinstance(body, dict):
        return False
    q = body.get("query")
    if not isinstance(q, str) or not q.strip():
        return False
    head = q.strip()[:40].lower()
    return not head.startswith("mutation") and not head.startswith("subscription")


def _effect(method: str, has_any_id: bool, is_admin: bool) -> Effect:
    m = method.upper()
    if is_admin and m in ("POST", "PUT", "PATCH", "DELETE"):
        return Effect.AUTHORITY
    if m == "GET":
        return Effect.OBJECT_ACCESS if has_any_id else Effect.NONE
    if m in ("PUT", "PATCH", "DELETE", "POST"):
        return Effect.STATE_GATE
    return Effect.NONE


def ingest_har(har: dict, principal_label: str, guard: ScopeGuard,
               pid: str | None = None) -> HarResult:
    entries = (((har or {}).get("log") or {}).get("entries")) or []
    if isinstance(entries, list):
        entries = entries[:MAX_HAR_ENTRIES]
    else:
        entries = []
    pid = pid or principal_label
    principal = Principal(pid=pid, label=principal_label)
    res = HarResult(principal=principal)
    endpoints: dict[str, Endpoint] = {}
    got_auth = got_profile = False

    for e in entries:
        req = (e or {}).get("request") or {}
        resp = (e or {}).get("response") or {}
        url = req.get("url", "")
        method = (req.get("method") or "GET").upper()
        if not url:
            continue
        host, path = split_host_path(url)
        if not guard.check_host(host).allowed:
            res.skipped_hosts[host] = res.skipped_hosts.get(host, 0) + 1
            continue
        res.hosts[host] = res.hosts.get(host, 0) + 1

        headers = _headers_map(req.get("headers"))
        query = _query_map(url)
        body = _body(req)
        if not got_auth:
            auth = {k: headers[k] for k in headers if k in _SECRET_HEADERS}
            if auth:
                principal.auth = auth; got_auth = True
        if not got_profile:
            prof = {k: headers[k] for k in headers if k in _PROFILE_HEADERS}
            if prof:
                principal.profile_headers = prof; got_profile = True

        ids = carriers.object_ids(method, path, query, headers, body)
        primary, all_ids = carriers.primary_and_all(ids)
        templ = template_path(path)
        is_admin = "/admin" in templ.lower() or "/internal" in templ.lower()
        gql_read = _is_graphql_read(path, body)
        key = endpoint_key(method, path)
        prov = Provenance.of(SourceKind.HAR, f"{principal_label}:{method} {path}")
        effect = Effect.OBJECT_ACCESS if (gql_read and ids) else _effect(method, bool(ids), is_admin)
        ep = Endpoint(method=method, path=templ, effect=effect,
                      provenance=[prov], observed_ids=list(all_ids))
        if key in endpoints:
            endpoints[key].merge(ep)
        else:
            endpoints[key] = ep

        status = int(resp.get("status", 0) or 0)
        readable = (method == "GET") or gql_read           # reads only, never mutations
        if readable and 200 <= status < 300 and primary is not None:
            res.accesses.append(ObservedAccess(
                principal_id=pid, endpoint_key=key, object_id=primary,
                path=path, method=method, provenance=prov,
                query=query, body=body, carrier=ids[0].carrier if ids else "path",
                all_ids=all_ids, safe_read=True))

    res.endpoints = [endpoints[k] for k in sorted(endpoints)]
    if not principal.auth:
        principal.is_anonymous = True
    return res
