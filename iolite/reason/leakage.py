"""
reason · leakage — mine INTENT from raw legal leakage the model doesn't already carry:

  * OpenAPI `security` / scopes        → an endpoint the developer marked protected
  * GraphQL @auth/@hasRole directives  → a field the developer role-guarded
  * HAR responses (401/403 + ownership phrases: "not the owner", "forbidden")
                                       → an endpoint the server actually authz-guards

Each yields a MINIMUM intended AccessClass per endpoint_key; intent.infer_intent
takes it when it is more restrictive than the model-derived class. Defensive: any
malformed/absent source is skipped, never fatal (QL2). Deterministic (QL4).
"""

from __future__ import annotations

import json
import re

from ..models import SurfaceModel
from ..normalize import endpoint_key, template_path
from .intent import AccessClass

_ADMIN_TOKENS = ("admin", "internal", "staff", "root", "superuser", "manage", "backoffice")
_ROLE_TOKENS = ("role", "write", "delete", "update", "manage", "scope", "grant")
_OWNER_PHRASES = ("not the owner", "not your", "you do not own", "you don't own",
                  "belongs to another", "forbidden", "not authorized", "not authorised",
                  "permission denied", "access denied", "not allowed", "unauthorized owner")
_GQL_DIRECTIVES = ("@auth", "@hasrole", "@requiresrole", "@requiresauth",
                   "@authenticated", "@isauthenticated", "@admin", "@hasscope",
                   "@haspermission", "@requiresscopes")
# feature-flag patterns (client-side gating leaks which features are meant to be gated)
_FLAG_RE = re.compile(
    r"(?:featureflags?|flags?|ld|launchdarkly|toggles?|gates?)\s*[.\[]\s*['\"]?"
    r"([A-Za-z][A-Za-z0-9_]{2,40})", re.IGNORECASE)
_FLAG_KV = re.compile(r"['\"]([A-Za-z][A-Za-z0-9_]*(?:admin|delete|manage|internal|staff|"
                      r"role|permission|beta|enable|can[A-Z])[A-Za-z0-9_]*)['\"]\s*:",
                      re.IGNORECASE)
_PRIV_FLAG_WORDS = ("admin", "delete", "manage", "internal", "staff", "role",
                    "permission", "superuser", "moderat", "backoffice", "impersonat")
# distinctive path tokens (>=4 chars, not generic) used to match leaked evidence to endpoints
_STOP_TOKENS = {"api", "v1", "v2", "v3", "http", "https", "com", "www", "get", "post",
                "put", "patch", "delete", "the", "and", "for", "with", "id"}


_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def _distinctive_tokens(text: str) -> set[str]:
    out: set[str] = set()
    for raw in re.findall(r"[A-Za-z][A-Za-z0-9_]{3,}", text):
        parts = [raw] + _CAMEL.findall(raw) + raw.split("_")   # whole + camel + snake
        for p in parts:
            pl = p.lower()
            if len(pl) >= 4 and pl not in _STOP_TOKENS:
                out.add(pl)
    return out


def _raise_matching(model: SurfaceModel, token: str, cls: AccessClass, out: dict) -> None:
    """Raise every model endpoint whose key contains a distinctive token from evidence."""
    tl = token.lower()
    if len(tl) < 4 or tl in _STOP_TOKENS:
        return
    for ep in model.endpoints:
        if tl in ep.lower():
            _raise(out, ep, cls)


def _raise(dst: dict, key: str, cls: AccessClass) -> None:
    from .intent import RANK
    if key not in dst or RANK.get(cls, -1) > RANK.get(dst[key], -1):
        dst[key] = cls


def _load(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _from_openapi(text: str, out: dict) -> None:
    try:
        doc = json.loads(text)
    except ValueError:
        return
    if not isinstance(doc, dict):
        return
    global_sec = bool(doc.get("security"))
    paths = doc.get("paths") or {}
    for raw_path, ops in paths.items() if isinstance(paths, dict) else []:
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            if not isinstance(op, dict):
                continue
            key = endpoint_key(method.upper(), template_path(str(raw_path)))
            sec = op.get("security", None)
            has_sec = bool(sec) or (sec is None and global_sec)
            blob = json.dumps(op.get("security") or doc.get("security") or "").lower()
            low = (str(raw_path) + " " + blob).lower()
            if any(t in low for t in _ADMIN_TOKENS):
                _raise(out, key, AccessClass.ADMIN_ONLY)
            elif any(t in blob for t in _ROLE_TOKENS):
                _raise(out, key, AccessClass.ROLE_RESTRICTED)
            elif has_sec:
                _raise(out, key, AccessClass.AUTHENTICATED)


def _from_graphql(text: str, model: SurfaceModel, out: dict) -> None:
    low = text.lower()
    if not any(d in low for d in _GQL_DIRECTIVES):
        return
    # field names near a directive occurrence
    guarded_admin, guarded_role = set(), set()
    for m in re.finditer(r"(\w+)\s*(\([^)]*\))?\s*:[^\n]*?(@\w+)", text):
        name, _args, directive = m.group(1), m.group(2), m.group(3).lower()
        if directive not in _GQL_DIRECTIVES:
            continue
        ctx = m.group(0).lower()
        (guarded_admin if any(t in ctx for t in _ADMIN_TOKENS) else guarded_role).add(name.lower())
    for ep in model.endpoints:
        # GraphQL endpoints in the model are keyed "<OP> <fieldName>"
        tail = ep.rsplit(" ", 1)[-1].lower()
        if tail in guarded_admin:
            _raise(out, ep, AccessClass.ADMIN_ONLY)
        elif tail in guarded_role:
            _raise(out, ep, AccessClass.ROLE_RESTRICTED)


def _from_har(text: str, out: dict) -> None:
    try:
        doc = json.loads(text)
    except ValueError:
        return
    entries = (((doc or {}).get("log") or {}).get("entries")) or []
    for e in entries if isinstance(entries, list) else []:
        try:
            req = e.get("request", {})
            resp = e.get("response", {})
            method = req.get("method", "GET")
            url = req.get("url", "")
            path = re.sub(r"^https?://[^/]+", "", url).split("?")[0] or "/"
            status = int(resp.get("status", 0) or 0)
            body = ((resp.get("content") or {}).get("text") or "")[:4000].lower()
        except Exception:      # noqa: BLE001
            continue
        phrase = any(p in body for p in _OWNER_PHRASES)
        if status in (401, 403) or phrase:
            key = endpoint_key(method.upper(), template_path(path))
            cls = AccessClass.ADMIN_ONLY if any(t in body for t in _ADMIN_TOKENS) else \
                (AccessClass.ROLE_RESTRICTED if "role" in body else AccessClass.OWNER_ONLY)
            _raise(out, key, cls)


def feature_flags(js_texts: list[str]) -> list[str]:
    """Privileged client feature-flag names — evidence a feature is meant to be gated
    (and is often gated CLIENT-SIDE ONLY, i.e. reachable on the server)."""
    flags: set[str] = set()
    for text in js_texts:
        for m in _FLAG_RE.finditer(text):
            flags.add(m.group(1))
        for m in _FLAG_KV.finditer(text):
            flags.add(m.group(1))
    return sorted(f for f in flags if any(w in f.lower() for w in _PRIV_FLAG_WORDS))


def _from_feature_flags(js_texts: list[str], model: SurfaceModel, out: dict) -> None:
    for flag in feature_flags(js_texts):
        for tok in _distinctive_tokens(flag):
            _raise_matching(model, tok, AccessClass.ROLE_RESTRICTED, out)


def _from_mobile(text: str, model: SurfaceModel, out: dict) -> None:
    """Strings dumped from the operator's OWN mobile app (strings/jadx/smali/plist).
    Admin/internal path strings → the endpoint is meant to be privileged."""
    for m in re.finditer(r"/[A-Za-z0-9_./{}-]{3,}", text):
        seg = m.group(0).lower()
        if any(w in seg for w in ("admin", "internal", "staff", "backoffice", "manage")):
            for tok in _distinctive_tokens(seg):
                _raise_matching(model, tok, AccessClass.ADMIN_ONLY, out)


def _from_commits(text: str, model: SurfaceModel, out: dict) -> None:
    """Public commit log/diff: authz-intent phrases near a path/name token → guarded."""
    phrases = ("admin only", "admin-only", "authorization", "access control", "authz",
               "idor", "owner check", "ownership", "permission", "restrict", "forbidden",
               "unauthorized", "rbac", "tenant isolation")
    for line in text.splitlines():
        low = line.lower()
        if not any(p in low for p in phrases):
            continue
        cls = AccessClass.ADMIN_ONLY if ("admin" in low or "rbac" in low) else (
            AccessClass.TENANT_ISOLATED if "tenant" in low else AccessClass.OWNER_ONLY)
        for tok in _distinctive_tokens(line):
            _raise_matching(model, tok, cls, out)


def mine_leakage(model: SurfaceModel, openapi_path: str = "", graphql_path: str = "",
                 har_paths: list[str] | None = None, js_paths: list[str] | None = None,
                 mobile_paths: list[str] | None = None,
                 commits_paths: list[str] | None = None) -> dict[str, AccessClass]:
    out: dict[str, AccessClass] = {}
    if openapi_path:
        _from_openapi(_load(openapi_path), out)
    if graphql_path:
        _from_graphql(_load(graphql_path), model, out)
    for h in (har_paths or []):
        _from_har(_load(h), out)
    js_texts = [_load(p) for p in (js_paths or [])]
    if js_texts:
        _from_feature_flags([t for t in js_texts if t], model, out)
    for mp in (mobile_paths or []):
        _from_mobile(_load(mp), model, out)
    for cp in (commits_paths or []):
        _from_commits(_load(cp), model, out)
    return dict(sorted(out.items()))
