"""
ghost_triage.py — rank the ghosts, and finish the time axis.

`temporal_diff` already computes archived-JS-minus-current ghosts. Two gaps remain before a
ghost is actionable:
  (1) the Wayback / gau URL FEED is a richer archive than JS blobs, and is not yet turned
      into ghosts — this does that (archived URL whose path is absent from the current
      capture → a ghost);
  (2) not every ghost matters: a stale /static/logo.png is noise, but /v1/admin/users/{id}
      is a zombie where the authz check was quietly dropped when the UI moved to /v2. This
      RANKS ghosts by authz-risk and flags version auth-regression against the live surface.

The top ghosts come out as probe paths for existence_oracle (pair 5) → confirm still-live →
capture_plan. Deterministic (QL4). Proposes, never adjudicates (QL5).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Endpoint, Provenance, SourceKind

_PRIV = ("admin", "internal", "root", "superuser", "sudo", "delete", "remove", "approve",
         "grant", "revoke", "role", "perm", "impersonate", "debug", "export", "backup",
         "config", "secret", "token", "key")
_ID = re.compile(r"/(\{[^}/]+\}|:\w+|\d+|[0-9a-fA-F]{8,}|%7b)", re.IGNORECASE)
_VER = re.compile(r"/v(\d+)(?=/|$)")
_PATH = re.compile(r"https?://[^/\s]+(/[^\s\"'<>?#]*)")
_WRITE = ("POST", "PUT", "PATCH", "DELETE")


@dataclass
class RankedGhost:
    key: str
    score: int
    reasons: list = field(default_factory=list)
    endpoint: object = None

    @property
    def probe_path(self) -> str:
        return self.key.split(" ", 1)[1] if " " in self.key else self.key


def ghosts_from_url_feed(archived_urls, current_keys) -> list:
    """Turn a Wayback/gau URL list into ghost Endpoints whose path is absent from current."""
    cur = set(current_keys or [])
    cur_paths = {k.split(" ", 1)[1] for k in cur if " " in k}
    out: dict = {}
    for u in archived_urls or []:
        if u.startswith("http"):
            m = _PATH.match(u)
            if not m:
                continue                                  # bare host, no path → skip
            path = m.group(1)
        else:
            path = u if u.startswith("/") else "/" + u
        path = (path.split("?", 1)[0].split("#", 1)[0].rstrip("/")) or "/"
        key = f"GET {path}"
        if path not in cur_paths and key not in cur and key not in out:
            ep = Endpoint(method="GET", path=path, provenance=[Provenance.of(
                SourceKind.OSINT_WAYBACK, key, note="archived URL, absent from current")])
            ep.role_hints.append("ghost:archived-url-feed")
            out[key] = ep
    return list(out.values())


def _score(path: str, method: str):
    s, why = 0, []
    pl = path.lower()
    hits = sorted({w for w in _PRIV if w in pl})
    if hits:
        s += 3 * len(hits); why.append(f"privileged({','.join(hits)})")
    if _ID.search(path):
        s += 2; why.append("object-id (BOLA surface)")
    if method.upper() in _WRITE:
        s += 2; why.append(f"write({method.upper()})")
    return s, why


def triage_ghosts(ghosts, *, current_keys=None) -> list:
    """Rank ghost Endpoints by authz-risk; flag version auth-regression against the current
    surface. Highest first — the operator confirms these live before anything else."""
    cur_paths = {k.split(" ", 1)[1] for k in (current_keys or []) if " " in k}
    cur_ver: dict = {}
    for p in cur_paths:
        if _VER.search(p):
            base = _VER.sub("/v#", p)
            cur_ver[base] = max(cur_ver.get(base, 0), int(_VER.search(p).group(1)))

    ranked = []
    for ep in ghosts:
        path = getattr(ep, "path", None) or (ep.key.split(" ", 1)[1] if hasattr(ep, "key") else str(ep))
        method = getattr(ep, "method", "GET")
        score, why = _score(path, method)
        if _VER.search(path):
            base, gv = _VER.sub("/v#", path), int(_VER.search(path).group(1))
            if base in cur_ver and cur_ver[base] > gv:
                score += 4
                why.append(f"auth-regression (ghost v{gv} < live v{cur_ver[base]})")
        key = getattr(ep, "key", None) or f"{method} {path}"
        if isinstance(ep, Endpoint):                       # record transparently on the model (QL4)
            ep.risk, ep.risk_reasons = score, list(why)
        ranked.append(RankedGhost(key=key, score=score, reasons=why, endpoint=ep))
    ranked.sort(key=lambda r: (-r.score, r.key))
    return ranked


def probe_targets(ranked, *, min_score: int = 2, top: int = 25) -> list:
    """The ghost paths worth confirming live — hand straight to existence_oracle.probe_existence."""
    return [r.probe_path for r in ranked if r.score >= min_score][:top]
