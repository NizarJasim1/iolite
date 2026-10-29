"""
existence_oracle.py — discover the HIDDEN / unwritten surface, safely.

Every other acquirer reads bytes the operator already holds (JS, HAR, archives), so an
endpoint that lives on the backend but appears in NO artifact and was NEVER called is
invisible — and that is exactly where a giant's authz zero-days hide (admin/internal/
legacy/aliased routes). This closes that blind spot WITHOUT becoming a fuzzer:

  1. HYPOTHESISE (offline, deterministic): from the STRUCTURE of the paths already observed,
     propose their unobserved siblings — a version bump (/v1↔/v2), a privileged variant
     (…/admin/… , …/internal/…), the collection↔item counterpart. No external wordlist.
  2. CONFIRM EXISTENCE only (ROE-gated, fail-closed): with a SAFE method (HEAD/OPTIONS/GET),
     in-scope, rate-limited, under attestation, distinguish 404 (absent, dropped) from
     401/403 (exists & PROTECTED — the prize), 405 (exists), 2xx (exists & reachable).
     It proves a path EXISTS; it never exploits it — ONYX still decides authz by Δstate.

Fail-closed: with no attestation / automation / scope (or no sender), NOTHING is sent — the
hypotheses are returned as ROE-gated leads. Confirms existence, never adjudicates (QL5).
Safe methods only (never a mutation). Own scope only (QL6). Deterministic (QL4).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_SAFE_METHODS = ("HEAD", "OPTIONS", "GET")
_VERSION = re.compile(r"/v(\d+)(?=/|$)")
_PRIV_PREFIXES = ("admin", "internal")
_GENERIC = {"api", "v1", "v2", "v3", "v4", "rest", "graphql", "gql", "bff", "gateway",
            "services", "service", "app", "web", "public"}


@dataclass
class PathHypothesis:
    path: str
    reason: str
    resource: str = ""


@dataclass
class ExistenceHit:
    path: str
    status: int
    verdict: str          # protected | reachable | exists | absent
    reason: str = ""

    @property
    def exists(self) -> bool:
        return self.verdict in ("protected", "reachable", "exists")


@dataclass
class ProbeResult:
    mode: str = "offline"                     # offline (nothing sent) | live
    sent: int = 0
    hits: list = field(default_factory=list)  # ExistenceHit that EXIST (candidates for ONYX)
    leads: list = field(default_factory=list)  # ROE-gated hypotheses (when offline)


def _resource(path: str) -> str:
    for seg in reversed([s for s in path.split("/") if s]):
        s = seg.strip().lower()
        if s and not s.startswith(("{", ":")) and s not in _GENERIC and s.isascii() and s.isalpha():
            return s.rstrip("s") if len(s) > 4 and s.endswith("s") else s
    return ""


def hidden_path_hypotheses(model, *, max_per_path: int = 6) -> list:
    """Propose unobserved sibling paths from the STRUCTURE of observed ones. Deterministic;
    never emits a path already observed (that is not hidden)."""
    observed = {getattr(ep, "path", "") for ep in getattr(model, "endpoints", {}).values()}
    observed = {p for p in observed if p}
    out: dict = {}

    def add(path, reason):
        if path and path not in observed and path not in out:
            out[path] = PathHypothesis(path=path, reason=reason, resource=_resource(path))

    for p in sorted(observed):
        segs = [s for s in p.split("/") if s]
        # (a) version siblings
        m = _VERSION.search(p)
        if m:
            cur = int(m.group(1))
            for v in (cur + 1, cur - 1, 2, 3):
                if v >= 1 and v != cur:
                    add(_VERSION.sub(f"/v{v}", p, count=1), f"observed /v{cur} → test /v{v} sibling")
        # (b) privileged / internal variants — insert before the resource segment
        res = _resource(p)
        if res:
            for i, s in enumerate(segs):
                if s.strip().lower().rstrip("s") == res:
                    for pref in _PRIV_PREFIXES:
                        if pref not in (x.lower() for x in segs):
                            nv = "/" + "/".join(segs[:i] + [pref] + segs[i:])
                            add(nv, f"resource '{res}' observed → test privileged variant '/{pref}/'")
                    break
        # (c) collection ↔ item counterpart
        if re.search(r"/\{[^}/]+\}$", p):
            add(re.sub(r"/\{[^}/]+\}$", "", p), "item observed → test the collection endpoint")
        elif segs and _resource(p):
            add(p.rstrip("/") + "/{id}", "collection observed → test the item endpoint")

    ranked = sorted(out.values(), key=lambda h: (h.resource, h.path))
    return ranked[: max_per_path * max(1, len(observed))]


def _classify(status: int) -> str:
    if status in (401, 403):
        return "protected"      # EXISTS and guarded — the highest-value hidden surface
    if 200 <= status < 300:
        return "reachable"      # exists and reachable as the probing principal
    if status in (405, 400, 409, 422, 429, 500, 501, 502, 503):
        return "exists"         # a real route (method/other error), not a 404
    return "absent"             # 404 / 410 / anything else → does not exist → dropped


def _gate_ok(engagement, host_ok) -> bool:
    """Fail-closed: live probing needs attestation + automation + in-scope + NOT dry-run."""
    if engagement is None:
        return False
    att = engagement.attested() if callable(getattr(engagement, "attested", None)) \
        else bool(getattr(engagement, "attestation", ""))
    return bool(att and getattr(engagement, "automation_permitted", False)
                and not getattr(engagement, "dry_run", True) and host_ok)


def probe_existence(hypotheses, *, engagement=None, sender=None, host="",
                    in_scope=True, rate_cap: int | None = None) -> ProbeResult:
    """Confirm EXISTENCE of hypothesised hidden paths, fail-closed. `sender(method,path)->status`
    is injected (a safe HEAD/OPTIONS/GET caller); without it, or without a passing gate, NOTHING
    is sent and the hypotheses come back as ROE-gated leads."""
    if sender is None or not _gate_ok(engagement, in_scope):
        return ProbeResult(mode="offline", sent=0, hits=[],
                           leads=[h if isinstance(h, PathHypothesis)
                                  else PathHypothesis(getattr(h, "path", None) or str(h),
                                                      getattr(h, "reason", "lead"))
                                  for h in hypotheses])
    cap = rate_cap if rate_cap is not None else getattr(engagement, "max_requests_per_min", 30)
    res = ProbeResult(mode="live")
    for h in hypotheses:
        if res.sent >= cap:
            res.leads.append(h)          # over budget → deferred lead (rate governor)
            continue
        path = getattr(h, "path", None) or str(h)
        status = -1
        for method in _SAFE_METHODS:     # HEAD, then OPTIONS, then GET — safe only
            status = int(sender(method, path))
            res.sent += 1
            if status != -1:
                break
        verdict = _classify(status)
        if verdict != "absent":
            res.hits.append(ExistenceHit(path=path, status=status, verdict=verdict,
                                         reason=getattr(h, "reason", "")))
    res.hits.sort(key=lambda x: ({"protected": 0, "reachable": 1, "exists": 2}.get(x.verdict, 9), x.path))
    return res
