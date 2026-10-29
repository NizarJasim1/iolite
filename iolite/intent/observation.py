"""
observation.py — DEEP extraction of one request/response into an authorization fact.

v1.18 flattened a response into a few scalars and looked only at "both accounts got it".
That throws away the richest intent signals. An `Observation` captures, per call:

  * ENFORCEMENT — the status CLASS (ALLOW / AUTHZ-DENY 403 / AUTHN-DENY 401 / MASKED 404 /
    RATE 429). A denial is first-class: it is how the true boundary is LEARNED by contrast.
  * IDENTITY — the acting principal's role / tenant / subject, decoded from the JWT CLAIMS
    in the request's own Authorization header (claims only; the token is never stored). This
    ties every fact to who did it, so ownership can be read, not guessed.
  * RELATIONSHIPS — the object's own id, and its server-STATED owner / parent / tenant / state
    (Zanzibar-style tuples), detected both by field name and, more reliably, by matching a
    response value to a known principal's subject.
  * STRUCTURE — every embedded object in arrays/nested bodies (a list endpoint reveals which
    ids a principal can ENUMERATE — the enumeration boundary and the chained-BOLA precursor).
  * TYPED FIELDS — each field classified id / secret / enum / timestamp / content.

Pure-stdlib, deterministic (QL4). Passive: parses only what the operator's own client sent and
received. Own accounts only (QL6).
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field

from .har_capture import _host_path, _template, _concrete_id
from .corroborate import _looks_discriminating
from .defense import classify as _classify_defense

_OWNER_NAMES = ("owner_id", "owner", "ownerid", "user_id", "userid", "created_by",
                "createdby", "account_id", "author_id", "customer_id", "sender_id", "uid")
_PARENT_NAMES = ("parent_id", "parent", "folder_id", "group_id", "collection_id", "project_id")
_TENANT_NAMES = ("tenant_id", "org_id", "organization_id", "organisation_id", "workspace_id",
                 "team_id", "company_id")
_STATE_NAMES = ("status", "state", "lifecycle", "stage", "phase")
_ID_NAMES = ("id", "_id", "uuid", "gid", "key", "slug")
_ROLE_CLAIMS = ("role", "roles", "scope", "scp", "permissions", "authorities", "groups")
_TENANT_CLAIMS = ("tenant", "tenant_id", "org", "org_id", "account", "aud")
_SUB_CLAIMS = ("sub", "user_id", "uid", "id", "email", "preferred_username")
_TS = re.compile(r"^\d{4}-\d\d-\d\dT|\d{10,13}$")


def _status_class(status: int) -> str:
    if 200 <= status < 300:
        return "ALLOW"
    if status == 401:
        return "AUTHN_DENY"
    if status == 403:
        return "AUTHZ_DENY"
    if status == 404:
        return "MASKED"           # 404 often masks a 403 (authz) — treated as a soft deny
    if status == 429:
        return "RATE"
    if status >= 500:
        return "ERROR"
    return "OTHER"


def _classify_value(name: str, value) -> str:
    sv = str(value)
    low = str(name).lower()
    if low in _ID_NAMES or low.endswith("_id") or low.endswith("id"):
        return "id"
    if _TS.search(sv):
        return "timestamp"
    if _looks_discriminating(value) and len(sv) >= 10 and any(c.isdigit() for c in sv):
        return "secret"
    if isinstance(value, bool) or (len(sv) <= 16 and sv.isalpha()):
        return "enum"
    if len(sv) > 40:
        return "content"
    return "scalar"


def _b64url(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def decode_jwt_claims(authorization: str) -> dict:
    """Return the JWT payload CLAIMS from an Authorization header (no verification, no token
    stored). Empty dict if not a JWT. Safe: these are the operator's own tokens; we read only
    the self-described claims that encode their role/tenant/subject."""
    if not authorization:
        return {}
    tok = authorization.split()[-1] if " " in authorization else authorization
    parts = tok.split(".")
    if len(parts) != 3:
        return {}
    try:
        return json.loads(_b64url(parts[1]).decode("utf-8", "replace")) or {}
    except Exception:
        return {}


def _first_claim(claims: dict, names) -> str:
    for n in names:
        for k, v in claims.items():
            if k.lower() == n and v not in (None, ""):
                if isinstance(v, list):
                    return ",".join(str(x) for x in v)
                return str(v)
    return ""


@dataclass
class Observation:
    principal: str
    method: str
    endpoint_key: str
    url_path: str
    host: str = ""
    object_id: str = ""
    object_type: str = ""
    owner_ref: str = ""           # server-stated owner id (from response)
    parent_ref: str = ""
    tenant_ref: str = ""
    state: str = ""
    status: int = 0
    enforce: str = "OTHER"        # ALLOW | AUTHN_DENY | AUTHZ_DENY | MASKED | RATE | ERROR
    defense: str = "OTHER"        # Defense signal (OK/RATE_LIMITED/WAF_BLOCK/CHALLENGE/AUTH_EXPIRED/FORBIDDEN_AUTHZ/…)
    waf_vendor: str = ""
    latency_ms: float = 0.0
    got_value: bool = False
    disc_values: set = field(default_factory=set)
    fields: dict = field(default_factory=dict)        # name -> typed class
    embedded: list = field(default_factory=list)      # [{id, owner, state, type}] from lists/nested
    # acting principal identity (from its own JWT claims)
    role: str = ""
    tenant: str = ""
    sub: str = ""
    seq: int = 0


def _walk_objects(node, depth=0, out=None):
    """Yield every dict that looks like an object (has an id-ish field) anywhere in the body."""
    out = out if out is not None else []
    if depth > 6:
        return out
    if isinstance(node, dict):
        if any(k.lower() in _ID_NAMES for k in node):
            out.append(node)
        for v in node.values():
            _walk_objects(v, depth + 1, out)
    elif isinstance(node, list):
        for x in node[:500]:
            _walk_objects(x, depth + 1, out)
    return out


def _obj_facts(obj: dict):
    def pick(names):
        for n in names:
            for k, v in obj.items():
                if k.lower() == n and isinstance(v, (str, int)) and str(v):
                    return str(v)
        return ""
    return {
        "id": pick(_ID_NAMES),
        "owner": pick(_OWNER_NAMES),
        "parent": pick(_PARENT_NAMES),
        "tenant": pick(_TENANT_NAMES),
        "state": pick(_STATE_NAMES),
    }


def observe(principal: str, method: str, url: str, *, req_headers=None, req_body=None,
            status: int = 0, resp_headers=None, resp_body=None, seq: int = 0,
            claims: dict | None = None, latency_ms: float = 0.0) -> Observation:
    """Deep-parse one exchange into an Observation. `claims` may be supplied directly (the
    live hook decodes the JWT client-side and sends claims, not the token)."""
    host, path = _host_path(url)
    method = (method or "GET").upper()
    claims = claims or decode_jwt_claims((req_headers or {}).get("authorization", "")
                                         or (req_headers or {}).get("Authorization", ""))
    role = _first_claim(claims, _ROLE_CLAIMS)
    ptenant = _first_claim(claims, _TENANT_CLAIMS)
    sub = _first_claim(claims, _SUB_CLAIMS)

    body = resp_body if isinstance(resp_body, (dict, list)) else {}
    objs = _walk_objects(body)
    oid = _concrete_id(path)
    is_collection = isinstance(body, list)
    top = {}
    # A single-resource response (dict, or a path with an id) addresses one object; a
    # collection (top-level list) addresses none — every item is an enumerated object.
    if not is_collection:
        for o in objs:
            f = _obj_facts(o)
            if f["id"] and (f["id"] == oid or not oid):
                top = f
                oid = oid or f["id"]
                break
        if not top and isinstance(body, dict) and objs:
            top = _obj_facts(objs[0])
            oid = oid or top.get("id", "")

    # embedded objects (collection items / nested) other than the addressed object
    embedded = []
    for o in objs:
        f = _obj_facts(o)
        if f["id"] and f["id"] != oid:
            embedded.append({"id": f["id"], "owner": f["owner"], "state": f["state"]})

    # discriminating values + typed fields (top-level scalars of the addressed object)
    disc, typed = set(), {}
    scalar_src = {}
    if isinstance(body, dict):
        scalar_src = body
    elif objs:
        scalar_src = objs[0]
    for k, v in (scalar_src.items() if isinstance(scalar_src, dict) else []):
        if isinstance(v, (str, int, float, bool)):
            typed[str(k).lower()] = _classify_value(k, v)
            if _looks_discriminating(v):
                disc.add(str(v))

    enforce = _status_class(status)
    dsig, vendor = _classify_defense(status, resp_headers, resp_body)

    return Observation(
        principal=principal, method=method, endpoint_key=f"{method} {_template(path)}",
        url_path=path, host=host, object_id=oid, object_type=_type_of(path),
        owner_ref=top.get("owner", ""), parent_ref=top.get("parent", ""),
        tenant_ref=top.get("tenant", "") or ptenant, state=top.get("state", ""),
        status=status, enforce=enforce, defense=dsig, waf_vendor=vendor, latency_ms=latency_ms,
        got_value=bool(disc and enforce == "ALLOW"), disc_values=disc, fields=typed,
        embedded=embedded, role=role, tenant=ptenant, sub=sub, seq=seq)


def _type_of(path: str) -> str:
    from .relation_model import _obj_type_of_path
    return _obj_type_of_path(path)
