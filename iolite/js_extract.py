"""
③ JS endpoint / param / role / flag miner (LinkFinder-class, deterministic).

This is the half ONYX explicitly does not do: pulling *undocumented* API surface
out of the frontend bundles a target serves publicly.

v0.2 — the miner now understands how paths are ACTUALLY built in
production bundles, not just clean quoted routes:

  * template literals            `/api/v1/orders/${id}`      → /api/v1/orders/{id}
  * string concatenation         "/api/v1/orders/" + id       → /api/v1/orders/{id}
  * multi-part concat chains     "/users/" + id + "/profile"  → /users/{id}/profile
  * const-prefixed composition   API + "/invoices/" + n       → <API>/invoices/{id}

A real concatenation resolver (forward + backward, with a const map) reconstructs
the full path; an identifier joined into a path becomes a {id} parameter. Method,
effect, roles and flags are derived as before. Everything is parse + regex, no
execution, no network (QL4). Recall/precision is MEASURED, not claimed — see
`calibrate.py` and `tests/test_calibration.py`.
"""

from __future__ import annotations

import re

from .models import Effect, Endpoint, Provenance, SourceKind
from .normalize import template_path, split_host_path
from .limits import (MAX_JS_BYTES, MAX_QUOTED_MATCHES, MAX_CONCAT_PARTS,
                     MAX_ENDPOINTS)

# a quoted path literal anywhere (single/double/backtick). We validate/compose after.
_QUOTE_OPEN = re.compile(r"""(['"`])(?=/)""")
_APIISH = re.compile(r"(?:^|/)(?:api|v\d+|graphql|gql|rest|internal|admin|service|"
                     r"gateway|bff|oauth|auth|account|user|order|payment)(?:/|$)",
                     re.IGNORECASE)
_ASSET = re.compile(r"\.(?:js|mjs|cjs|css|scss|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|"
                    r"map|webp|mp4|webm|json|txt|xml|wasm)(?:$|\?|#)", re.IGNORECASE)

_METHOD_CALL = re.compile(r"\.(get|post|put|patch|delete|head)\s*\(\s*$", re.IGNORECASE)
_METHOD_FIELD = re.compile(r"""method\s*[:=]\s*['"](get|post|put|patch|delete|head)['"]""",
                           re.IGNORECASE)

_ROLE_HINT = re.compile(
    r"\b(is_?admin|isAdmin|superuser|super_admin|role\s*[:=]|roles?\b|"
    r"privilege|permission|internal|staff|is_?staff|scope\s*[:=]|acl)\b", re.IGNORECASE)
_ADMIN_PATH = re.compile(r"/(admin|internal|manage|backoffice|superuser|staff|sys|ops)(/|$)",
                         re.IGNORECASE)
_FLAG = re.compile(r"\b(feature[_A-Za-z0-9]*|flag[_A-Za-z0-9]*|enable[A-Z][A-Za-z0-9]*)\b")
_TPARAM = re.compile(r"\$\{[^}/]+\}|\{[^}/]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>/]+>")

_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_CONST_ASSIGN = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['"`](/[^'"`\s]{1,200})['"`]""")


# --------------------------------------------------------------------------- #
# low-level scanners                                                          #
# --------------------------------------------------------------------------- #
def _read_string(text: str, i: int):
    """text[i] is a quote. Return (content, index_after_close) or (None, i)."""
    q = text[i]
    if q not in "'\"`":
        return None, i
    j, buf = i + 1, []
    n = len(text)
    while j < n:
        c = text[j]
        if c == "\\" and j + 1 < n:
            buf.append(text[j + 1]); j += 2; continue
        if c == q:
            return "".join(buf), j + 1
        buf.append(c); j += 1
    return None, i


def _skip_ws_fwd(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    return i


def _skip_ws_back(text: str, i: int) -> int:
    while i >= 0 and text[i] in " \t\r\n":
        i -= 1
    return i


def _const_map(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _CONST_ASSIGN.finditer(text):
        name, val = m.group(1), m.group(2)
        if name not in out:
            out[name] = val
    return out


def _resolve_concat(text: str, qi: int, const_map: dict[str, str]):
    """Compose a full path from a concatenation chain that starts at the quoted
    string opening at qi. Returns (raw_path, end_index, had_dynamic_id)."""
    content, end = _read_string(text, qi)
    if content is None:
        return None, qi, False
    parts = [content]
    dynamic = False

    # forward: ( + ( "str" | IDENT ) )*  — bounded against a pathological chain
    k = end
    n = len(text)
    while len(parts) < MAX_CONCAT_PARTS:
        k2 = _skip_ws_fwd(text, k)
        if k2 >= n or text[k2] != "+":
            break
        k3 = _skip_ws_fwd(text, k2 + 1)
        if k3 < n and text[k3] in "'\"`":
            s, e = _read_string(text, k3)
            if s is None:
                break
            parts.append(s); k = e; continue
        mi = _IDENT.match(text, k3)
        if mi:
            ident = mi.group(0)
            if ident in const_map:
                parts.append(const_map[ident])
            else:
                parts.append("{id}"); dynamic = True
            k = mi.end(); continue
        break

    # backward: IDENT + "..."  → prepend a const base if present
    prefix = ""
    b = _skip_ws_back(text, qi - 1)
    if b >= 0 and text[b] == "+":
        bb = _skip_ws_back(text, b - 1)
        e = bb
        while e >= 0 and (text[e].isalnum() or text[e] in "_$"):
            e -= 1
        ident = text[e + 1:bb + 1]
        if ident and ident in const_map:
            prefix = const_map[ident]

    raw = prefix + "".join(parts)
    raw = re.sub(r"/{2,}", "/", raw)
    return raw, k, dynamic


def _method_near(text: str, pos: int, window: int = 60) -> str:
    lo = max(0, pos - window)
    before = text[lo:pos]
    if _METHOD_CALL.search(before):
        return _METHOD_CALL.search(before).group(1).upper()
    hi = min(len(text), pos + window)
    fm = None
    for mm in _METHOD_FIELD.finditer(text[lo:hi]):
        fm = mm
    return fm.group(1).upper() if fm else "GET"


def _effect_for(method: str, path: str) -> Effect:
    m = method.upper()
    has_id = "{id}" in template_path(path)
    if _ADMIN_PATH.search(path) and m in ("POST", "PUT", "PATCH", "DELETE"):
        return Effect.AUTHORITY
    if m == "GET":
        return Effect.OBJECT_ACCESS if has_id else Effect.NONE
    if m in ("PUT", "PATCH", "DELETE", "POST"):
        return Effect.STATE_GATE
    return Effect.NONE


def extract_endpoints(js_text: str, locator: str,
                      source: SourceKind = SourceKind.JS) -> list[Endpoint]:
    """Mine a JS blob into a deterministic list of Endpoints (sorted by key)."""
    if len(js_text) > MAX_JS_BYTES:            # bound the scan (QL4 / limits)
        js_text = js_text[:MAX_JS_BYTES]
    const_map = _const_map(js_text)
    found: dict[str, Endpoint] = {}
    file_roles = sorted({m.group(0).lower() for m in _ROLE_HINT.finditer(js_text)})[:8]

    consumed_until = -1
    scanned = 0
    for om in _QUOTE_OPEN.finditer(js_text):
        scanned += 1
        if scanned > MAX_QUOTED_MATCHES or len(found) >= MAX_ENDPOINTS:
            break
        qi = om.start()
        if qi < consumed_until:
            continue
        raw, end, _dyn = _resolve_concat(js_text, qi, const_map)
        consumed_until = end
        if raw is None:
            continue
        if raw.startswith("//") or "://" in raw:
            _host, raw = split_host_path(raw)
        if not raw.startswith("/") or _ASSET.search(raw):
            continue
        templ = template_path(raw)
        if not _APIISH.search(templ) and "{id}" not in templ:
            continue  # keep only api-ish or clearly-parameterised routes (low FP)

        method = _method_near(js_text, qi)
        lo, hi = max(0, qi - 32), min(len(js_text), end + 32)
        local = js_text[lo:hi]
        roles = []
        if _ADMIN_PATH.search(templ):
            roles.append("admin-path")
        if _ROLE_HINT.search(local):
            roles.append("role-guarded")
        params = sorted({p.strip("${}:<>") for p in _TPARAM.findall(raw)})
        prov = Provenance.of(source, f"{locator}@{qi}",
                             note="method inferred from call site" if method != "GET" else "")
        ep = Endpoint(method=method, path=templ, effect=_effect_for(method, raw),
                      params=[p for p in params if p], provenance=[prov], role_hints=roles)
        if ep.key in found:
            found[ep.key].merge(ep)
        else:
            found[ep.key] = ep

    for ep in found.values():
        if any("admin" in r or "role" in r for r in ep.role_hints) and file_roles:
            for r in file_roles:
                tag = f"hint:{r}"
                if tag not in ep.role_hints:
                    ep.role_hints.append(tag)

    return [found[k] for k in sorted(found)]


def extract_flags(js_text: str) -> list[str]:
    return sorted({m.group(1) for m in _FLAG.finditer(js_text) if len(m.group(1)) > 5})[:50]
