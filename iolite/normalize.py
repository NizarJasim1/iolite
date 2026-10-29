"""
Path normalisation + object-id recognition.

CRITICAL: the endpoint-key form produced here MUST match ONYX/AuthPath's
`HTTPRequest.endpoint_key()` (`authpath/models.py`) so the contract IOLITE emits
lines up with what ONYX computes at scan time. The id-recognition rules below are a
faithful port of ONYX's `segments()`:

  a segment is an object-id if it is
    * numeric, OR
    * a long hex / uuid, OR
    * follows a collection noun (previous segment ends in 's', len>2) and is
      itself identifier-like and not an action word / self-alias.

This is cosmetic routing only — it decides grouping, never a verdict (QL5).
"""

from __future__ import annotations

import re

# Action words that follow an id (e.g. /orders/{id}/fulfil) — never themselves ids.
ACTION_SEGMENTS = {
    "fulfil", "fulfill", "ship", "cancel", "approve", "reject", "redeem",
    "price", "checkout", "pay", "settle", "refund", "activate", "deactivate",
    "lock", "unlock", "verify", "confirm", "submit", "complete", "location",
}
# Self-referential aliases resolve to the caller, never a shared object id.
SELF_ALIASES = {"me", "self", "current", "mine", "my", "current_user"}

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Recognises every route-parameter syntax a frontend bundle uses so they all
# normalise to a single {id}: ES template `${x}`, Express `:x`, OpenAPI `{x}`,
# Rails/Flask `<x>`.
_TEMPLATE_PARAM = re.compile(r"\$\{[^}/]+\}|\{[^}/]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>/]+>")


def _looks_like_hex_id(seg: str) -> bool:
    if _UUID_RE.match(seg):
        return True
    return len(seg) >= 16 and all(c in "0123456789abcdefABCDEF-" for c in seg)


def _ident_like(seg: str) -> bool:
    if not seg or seg.lower() in SELF_ALIASES:
        return False
    return len(seg) <= 64 and all(c.isalnum() or c in "-_.@" for c in seg)


def is_object_id(seg: str, prev: str) -> bool:
    if seg.isdigit():
        return True
    if _looks_like_hex_id(seg):
        return True
    if (prev.endswith("s") and len(prev) > 2
            and seg.lower() not in ACTION_SEGMENTS
            and seg.lower() not in SELF_ALIASES
            and _ident_like(seg) and not seg.isalpha()):
        # a bare alpha word after a collection noun is usually a sub-resource name,
        # not an id (e.g. /users/settings); require a non-pure-alpha token or a
        # template marker to call it an id, keeping FP-routing low.
        return True
    return False


def segments(path: str) -> list[tuple[str, bool]]:
    """Return [(segment, is_object_id)] for a concrete or templated path."""
    raw = [s for s in (path or "").strip("/").split("/") if s]
    out: list[tuple[str, bool]] = []
    for i, seg in enumerate(raw):
        prev = raw[i - 1] if i > 0 else ""
        if _TEMPLATE_PARAM.fullmatch(seg):
            out.append((seg, True))
            continue
        out.append((seg, is_object_id(seg, prev)))
    return out


def template_path(path: str) -> str:
    """Collapse id-bearing segments to {id}."""
    parts = ["{id}" if is_id else seg for seg, is_id in segments(path)]
    return "/" + "/".join(parts) if parts else "/"


def endpoint_key(method: str, path: str) -> str:
    """`METHOD /path/with/{id}` — identical to ONYX's endpoint_key for REST paths."""
    return f"{(method or 'GET').upper()} {template_path(path)}"


def object_ids(path: str) -> list[str]:
    """Concrete id segments in a path (deterministic order, de-duplicated)."""
    ids, seen = [], set()
    for seg, is_id in segments(path):
        if is_id and not _TEMPLATE_PARAM.fullmatch(seg) and seg not in seen:
            seen.add(seg)
            ids.append(seg)
    return ids


def split_host_path(url: str) -> tuple[str, str]:
    """('https://api.x.com/a/b?q=1') -> ('api.x.com', '/a/b'). Query stripped."""
    if "://" in url:
        rest = url.split("://", 1)[1]
    else:
        rest = url
    host = rest.split("/", 1)[0].split(":", 1)[0].lower()
    path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    path = path.split("?", 1)[0].split("#", 1)[0]
    return host, path or "/"
