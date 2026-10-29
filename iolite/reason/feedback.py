"""
feedback.py — the adaptive loop that closes the chain.

Every stage so far produces an ORDERED set of candidates for ONYX to confirm by Δstate. When
ONYX confirms one, that verdict is evidence about a whole NEIGHBOURHOOD, not just one URL: a
broken-object-authz on a 'order' usually means its siblings leak too; a confirmed v1
auth-regression means the whole /v1 family is suspect; a reachable /admin route means the
privileged prefix is soft. This feeds that signal back and RE-WEIGHTS discovery and capture
toward the neighbours of what was already confirmed — so the second pass spends budget where
the first pass just proved vulnerability lives.

It writes into the SAME transparent ledger as triage (`ep.risk` + "+N reason" lines): bounded,
auditable, no ML (QL4). It only re-orders candidates; ONYX still confirms each by Δstate (QL5).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..intent.relation_model import _obj_type_of_path

_VER = re.compile(r"/v(\d+)(?=/|$)")
_PRIV = ("admin", "internal", "root", "superuser", "debug", "export", "backup", "config")
_WRITE = ("POST", "PUT", "PATCH", "DELETE")
_CAP = 15                      # a learned signal re-orders; it must not swamp the base authz score


@dataclass
class ConfirmedFinding:
    family: str = ""           # bola / bopla / bfla / tenant / auth_regression (ONYX's verdict)
    path: str = ""
    object_type: str = ""
    host: str = ""
    method: str = "GET"

    def __post_init__(self):
        if not self.object_type and self.path:
            self.object_type = _obj_type_of_path(self.path) or ""


def _ver_family(path: str) -> str:
    m = _VER.search(path)
    return m.group(0) if m else ""      # "/v1" — a confirmed hole implicates its whole version family


def _priv_prefix(path: str) -> str:
    pl = path.lower()
    return next((w for w in _PRIV if w in pl), "")


def _bonus(path: str, otype: str, method: str, host: str, findings) -> tuple[int, list]:
    """Transparent, bounded boost for a candidate that shares a feature with a CONFIRMED hole."""
    score, why = 0, []
    otype = (otype or _obj_type_of_path(path) or "").lower()
    vf, pp = _ver_family(path), _priv_prefix(path)
    for f in findings:
        fam = f.family or "authz"
        if otype and otype == (f.object_type or "").lower():
            score += 8; why.append(f"+8 learned: same object-type '{otype}' as confirmed {fam}")
        if vf and vf == _ver_family(f.path):
            score += 4; why.append(f"+4 learned: same version family '{vf}' as confirmed {fam}")
        if pp and pp == _priv_prefix(f.path):
            score += 4; why.append(f"+4 learned: same privileged prefix '/{pp}' as confirmed {fam}")
        if host and f.host and host.lower() == f.host.lower():
            score += 2; why.append(f"+2 learned: same host as confirmed {fam}")
        if method.upper() in _WRITE and f.method.upper() in _WRITE and method.upper() == f.method.upper():
            score += 3; why.append(f"+3 learned: same write verb {method.upper()} as confirmed {fam}")
    if score > _CAP:
        why.append(f"(capped {score}→{_CAP})"); score = _CAP
    return score, why


def reweight(endpoints, findings, *, host: str = "") -> list:
    """Re-rank mined endpoints by proximity to confirmed findings. Mutates ep.risk /
    ep.risk_reasons in place (same ledger as triage), returns highest-first."""
    if not findings:
        return list(endpoints)
    for ep in endpoints:
        add, why = _bonus(getattr(ep, "path", ""), _obj_type_of_path(getattr(ep, "path", "")),
                          getattr(ep, "method", "GET"), host, findings)
        if add:
            ep.risk = getattr(ep, "risk", 0) + add
            ep.risk_reasons = list(getattr(ep, "risk_reasons", [])) + why
    return sorted(endpoints, key=lambda e: (-getattr(e, "risk", 0), getattr(e, "key", "")))


def reweight_capture(steps, findings) -> list:
    """Bump capture-plan steps whose object type / write flow sits in a confirmed
    neighbourhood, then re-order by the unlocked-test estimate. Closes the loop on capture."""
    if not findings:
        return list(steps)
    for s in steps:
        otype = (getattr(s, "object_type", "") or "").lower()
        add = 0
        for f in findings:
            if otype and otype == (f.object_type or "").lower():
                add += 8
            if any(m in _WRITE for m in getattr(s, "methods", [])) and f.method.upper() in _WRITE:
                add += 3
        if add:
            add = min(add, _CAP)
            s.est_tests = getattr(s, "est_tests", 0) + add
            s.why = (getattr(s, "why", "") + f" | +{add} learned: neighbourhood of a confirmed finding").strip()
    return sorted(steps, key=lambda s: (-getattr(s, "est_tests", 0), getattr(s, "object_type", "")))
