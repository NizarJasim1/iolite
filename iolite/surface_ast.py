"""
surface_ast — deeper static recovery of the API surface from artifacts you already
hold, targeting two shapes `js_extract` (quoted-literal scanner) under-recovers:

  1. request-CONFIG object literals — axios/fetch/$http options where the URL and the
     verb are SEPARATE keys:  request({ url: '/api/admin/users', method: 'POST' }).
     The verb lives in a sibling key, not at a call site, so a call-site method
     heuristic misses it.
  2. privileged client ROUTE tables — `path: '/admin/...'`, `<Route path="…">`. These
     are UI leads (what the client CAN reach), returned separately as hints — never
     emitted as probeable API endpoints (they are not API calls; that would pollute
     the contract).

Static recovery degrades on heavy obfuscation (the honest limit every static tool
shares — see jsluice). The obfuscation-PROOF surface comes from `surface_runtime`
(the client deobfuscates itself at run time). This module + gql_client + runtime
together are the Point-2 "deep acquisition" stack.

Pure stdlib, deterministic (QL4). Passive — reads held bytes, sends nothing.
Additive: nothing here runs unless `deep` acquisition is explicitly requested.
"""

from __future__ import annotations

import re

from .models import Effect, Endpoint, Provenance, SourceKind
from .normalize import template_path
from .limits import MAX_JS_BYTES
from . import gql_client

_URL_KEY = re.compile(r"""\b(?:url|uri|path|endpoint)\s*:\s*(['"])(/[^'"]{1,200})\1""",
                      re.IGNORECASE)
_METHOD_KEY = re.compile(r"""\bmethod\s*:\s*(['"])(get|post|put|patch|delete|head)\1""",
                         re.IGNORECASE)
_ROUTE_KEY = re.compile(r"""\bpath\s*:\s*(['"])([A-Za-z0-9_./:{}-]{1,120})\1""")
_JSX_ROUTE = re.compile(r"""<Route\b[^>]*\bpath\s*=\s*(['"])([^'"]{1,120})\1""")
_APIISH = re.compile(r"(?:^|/)(?:api|v\d+|graphql|gql|rest|internal|admin|service|"
                     r"gateway|bff|oauth|auth|account|user|order|payment)(?:/|$)",
                     re.IGNORECASE)
_ADMIN = re.compile(r"/(admin|internal|manage|backoffice|superuser|staff|sys|ops|"
                    r"moderat|billing|console)(/|$)", re.IGNORECASE)
_ASSET = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|woff2?|ico|map|json|txt|xml)(?:$|\?|#)",
                    re.IGNORECASE)


def _effect_for(method: str, path: str) -> Effect:
    m = method.upper()
    has_id = "{id}" in template_path(path)
    if _ADMIN.search(path) and m in ("POST", "PUT", "PATCH", "DELETE"):
        return Effect.AUTHORITY
    if m == "GET":
        return Effect.OBJECT_ACCESS if has_id else Effect.NONE
    if m in ("PUT", "PATCH", "DELETE", "POST"):
        return Effect.STATE_GATE
    return Effect.NONE


def extract_config_endpoints(text: str, locator: str) -> list[Endpoint]:
    """Recover endpoints from request-config object literals. The verb is taken from
    the nearest `method:` key within a bounded window; default GET."""
    if not text:
        return []
    if len(text) > MAX_JS_BYTES:
        text = text[:MAX_JS_BYTES]
    out: dict[str, Endpoint] = {}
    for m in _URL_KEY.finditer(text):
        raw = m.group(2)
        if _ASSET.search(raw):
            continue
        templ = template_path(raw)
        if not _APIISH.search(templ) and "{id}" not in templ:
            continue
        lo, hi = max(0, m.start() - 140), min(len(text), m.end() + 140)
        win = text[lo:hi]
        method = "GET"
        mm = None
        for cand in _METHOD_KEY.finditer(win):
            mm = cand
        if mm:
            method = mm.group(2).upper()
        roles = ["admin-path"] if _ADMIN.search(templ) else []
        ep = Endpoint(method=method, path=templ, effect=_effect_for(method, raw),
                      provenance=[Provenance.of(SourceKind.JS, f"{locator}@{m.start()}",
                                                note="request-config object literal")],
                      role_hints=roles)
        if ep.key in out:
            out[ep.key].merge(ep)
        else:
            out[ep.key] = ep
    return [out[k] for k in sorted(out)]


def privileged_routes(text: str) -> list[str]:
    """Admin/privileged client ROUTE paths (UI leads, not API endpoints). These name
    the privileged areas and drive Tier-2 guided self-navigation. Deterministic."""
    if not text:
        return []
    found: set[str] = set()
    for rx in (_ROUTE_KEY, _JSX_ROUTE):
        for m in rx.finditer(text[:MAX_JS_BYTES]):
            p = m.group(2)
            if _ADMIN.search("/" + p.lstrip("/")):
                found.add("/" + p.lstrip("/"))
    return sorted(found)


def deep_recover(pairs: list[tuple[str, str]]) -> list[Endpoint]:
    """Merge deep-static recovery over (text, locator) artifacts: request-config
    endpoints + client-derived GraphQL operations. Deterministic, deduplicated."""
    out: dict[str, Endpoint] = {}
    for text, loc in pairs:
        for ep in extract_config_endpoints(text, loc) + \
                gql_client.extract_graphql_operations(text, loc):
            if ep.key in out:
                out[ep.key].merge(ep)
            else:
                out[ep.key] = ep
    return [out[k] for k in sorted(out)]
