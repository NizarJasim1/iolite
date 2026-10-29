"""
③ OpenAPI / Swagger → endpoints.

Thin, tolerant reader that turns a declared contract into IOLITE Endpoints with
OPENAPI provenance. This complements ONYX's own `discovery.parse_openapi`; here it
feeds the *unified* surface model so declared routes rank alongside JS-mined and
HAR-observed ones. Conservative effect hints, bounded against hostile documents.
"""

from __future__ import annotations

import re

from .models import Effect, Endpoint, Provenance, SourceKind
from .normalize import template_path

_MAX_PATHS = 5000
_PARAM = re.compile(r"\{[^}/]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>/]+>")


def _base(doc: dict) -> str:
    try:
        servers = doc.get("servers") or []
        if servers and isinstance(servers[0], dict):
            url = servers[0].get("url", "")
            m = re.search(r"https?://[^/]+(/.*)$", url)
            return (m.group(1) if m else (url if url.startswith("/") else "")).rstrip("/")
        if doc.get("basePath"):
            return str(doc["basePath"]).rstrip("/")
    except Exception:
        pass
    return ""


def _effect(method: str, has_param: bool) -> Effect:
    m = method.upper()
    if m == "GET":
        return Effect.OBJECT_ACCESS if has_param else Effect.NONE
    if m in ("PUT", "PATCH", "DELETE"):
        return Effect.STATE_GATE if has_param else Effect.STATE_GATE
    if m == "POST":
        return Effect.STATE_GATE
    return Effect.NONE


def parse_openapi(doc: dict, locator: str = "openapi") -> list[Endpoint]:
    if not isinstance(doc, dict):
        return []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _base(doc)
    out: dict[str, Endpoint] = {}
    for raw_path, item in list(paths.items())[:_MAX_PATHS]:
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        full = (base + raw_path) if not raw_path.startswith(base or "\x00") else raw_path
        full = re.sub(r"/{2,}", "/", full) or "/"
        has_param = bool(_PARAM.search(full))
        params = sorted({p.strip("{}:<>") for p in _PARAM.findall(full)})
        for method, _op in item.items():
            mu = method.upper()
            if mu not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            ep = Endpoint(
                method=mu, path=template_path(full), effect=_effect(mu, has_param),
                params=params,
                provenance=[Provenance.of(SourceKind.OPENAPI, f"{locator}:{mu} {full}")],
            )
            if ep.key in out:
                out[ep.key].merge(ep)
            else:
                out[ep.key] = ep
    return [out[k] for k in sorted(out)]
