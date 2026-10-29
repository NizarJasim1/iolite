"""
har_capture.py — turn real multi-account HAR captures into response-bearing evidence.

This closes the single most damaging gap found in the self-audit: `iolite.har_ingest`
reads only request bodies and the response STATUS, throwing the response BODY away — so
`corroborate` (confirm a bug offline from captures, 0 requests) could never fire on real
data. Here we parse the response content too, producing `CapturedExchange` records with
the fields and ids the server actually returned, plus an `owned` flag inferred from the
capture (who CREATED the object vs merely accessed it).

Legal/scope: if `scope_hosts` is given, only in-scope hosts are ingested — out-of-scope
traffic in a messy HAR is dropped, never analysed. Own captures only (QL6). No requests
are sent; this is pure offline parsing (QL2 passive).

Typical layout: one HAR per account, named so the principal is recoverable
(`alice.har`, `bob.har`, or `*_A.har` / `*_B.har`). `exchanges_from_dir` auto-detects.
"""
from __future__ import annotations

import json
import os

from .capture import CapturedExchange, _scalars

_MUTATING = ("POST", "PUT", "PATCH", "DELETE")
_SELF = {"me", "self", "current", "mine", "profile"}


def _load_har(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except Exception:
        return []
    return (((data or {}).get("log") or {}).get("entries")) or []


def _host_path(url: str):
    s = url.split("://", 1)[-1]
    host = s.split("/", 1)[0].split("?", 1)[0]
    path = "/" + s[len(host):].lstrip("/")
    path = path.split("?", 1)[0].split("#", 1)[0]
    return host.lower(), path


def _template(path: str) -> str:
    """Replace concrete id-looking segments with {id} so an endpoint key is stable."""
    out = []
    for seg in path.split("/"):
        s = seg
        if s.isdigit() and len(s) >= 1:
            out.append("{id}")
        elif len(s) >= 8 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
            out.append("{id}")               # uuid/hash/gid-ish
        elif len(s) >= 20:
            out.append("{id}")
        else:
            out.append(s)
    return "/".join(out)


def _concrete_id(path: str) -> str:
    """The last concrete, id-looking segment of a path (the primary object id)."""
    best = ""
    for seg in path.split("/"):
        s = seg
        if s.lower() in _SELF:
            continue
        if s.isdigit() or (len(s) >= 8 and any(c.isdigit() for c in s)) or len(s) >= 20:
            best = s
    return best


def _resp_json(entry: dict):
    resp = (entry or {}).get("response") or {}
    content = (resp.get("content") or {})
    text = content.get("text")
    if text is None:
        return {}
    if content.get("encoding") == "base64":
        import base64
        try:
            text = base64.b64decode(text).decode("utf-8", "replace")
        except Exception:
            return {}
    if isinstance(text, (dict, list)):
        return text
    try:
        return json.loads(text)
    except Exception:
        return {}


def _req_body(entry: dict):
    req = (entry or {}).get("request") or {}
    pd = req.get("postData") or {}
    text = pd.get("text")
    if text is None:
        return {}
    try:
        return json.loads(text) if isinstance(text, str) else text
    except Exception:
        return {}


def exchanges_from_har(path: str, principal: str, *, scope_hosts: set | None = None,
                       start_seq: int = 0) -> list[CapturedExchange]:
    """Parse ONE principal's HAR into response-bearing exchanges. Deterministic."""
    out = []
    created_ids: set = set()              # ids this principal CREATED (owns) in this capture
    seq = start_seq
    for entry in _load_har(path):
        req = (entry or {}).get("request") or {}
        url = req.get("url", "")
        if not url:
            continue
        host, p = _host_path(url)
        if scope_hosts is not None and host not in scope_hosts:
            continue                       # out-of-scope -> never ingested
        method = (req.get("method") or "GET").upper()
        resp = (entry or {}).get("response") or {}
        status = int(resp.get("status", 0) or 0)
        rj = _resp_json(entry)
        rbody = _req_body(entry)
        oid = _concrete_id(p)
        rfields = _scalars(rj if isinstance(rj, dict) else {})
        # id disclosed in the response (nested list of objects with ids) — for chaining
        rids = _response_ids(rj)
        # tenant hint from request/response
        tenant = ""
        for src in (rbody if isinstance(rbody, dict) else {}, rfields):
            for k, v in (src.items() if isinstance(src, dict) else []):
                if k.lower() in ("tenant_id", "org_id", "organization_id", "workspace_id") and v:
                    tenant = str(v)
        # owned inference: a successful CREATE whose response carries the new id => owned
        owned = False
        if method in _MUTATING and 200 <= status < 300:
            new_id = str(rfields.get("id") or rfields.get("_id") or oid or "")
            if new_id:
                created_ids.add(new_id)
                owned = True
                oid = oid or new_id
        elif oid and oid in created_ids:
            owned = True
        elif any(seg.lower() in _SELF for seg in p.split("/")):
            owned = True                   # /me, /self => the principal's own object
        out.append(CapturedExchange(
            principal=principal, endpoint_key=f"{method} {_template(p)}", method=method,
            object_id=oid, owned=owned, request_fields=_scalars(rbody if isinstance(rbody, dict) else {}),
            response_fields=rfields, response_ids=rids, status=status, tenant=tenant, seq=seq))
        seq += 1
    return out


def _response_ids(rj) -> list:
    """Object ids disclosed in a response body (top-level, list items, nested 'id' keys)."""
    ids = set()
    def rec(v, depth=0):
        if depth > 4:
            return
        if isinstance(v, dict):
            for k, val in v.items():
                if k.lower() in ("id", "_id", "uuid", "gid") and isinstance(val, (str, int)):
                    ids.add(str(val))
                rec(val, depth + 1)
        elif isinstance(v, list):
            for x in v[:200]:
                rec(x, depth + 1)
    rec(rj)
    return sorted(ids)


def _principal_of(filename: str) -> str:
    """Recover the principal label from a HAR filename."""
    base = os.path.basename(filename).rsplit(".", 1)[0]
    for sep in ("_", "-", "."):
        if sep in base:
            tail = base.split(sep)[-1]
            if tail:
                return tail
    return base or "P"


def exchanges_from_dir(folder: str, *, scope_hosts: set | None = None) -> list[CapturedExchange]:
    """Load every *.har in a folder as one principal each (label from filename), merge,
    and fill response_ids-based cross references. Deterministic order."""
    hars = sorted(f for f in os.listdir(folder) if f.lower().endswith(".har"))
    out, seq = [], 0
    for f in hars:
        pid = _principal_of(f)
        ex = exchanges_from_har(os.path.join(folder, f), pid,
                                scope_hosts=scope_hosts, start_seq=seq)
        out.extend(ex)
        seq += len(ex)
    return out


def principals_in(exchanges) -> list:
    return sorted({e.principal for e in exchanges})
