"""
mobile_mine.py — mine the surface the WEB client never reveals (the CLIENT axis).

A target's mobile app (and any partner/B2B SDK) is a DIFFERENT client of the SAME backend:
it embeds base URLs, API paths, staging/internal hosts and privileged routes the web bundle
never ships. Everyone audits the web; the mobile binary is where the un-audited authz
surface hides. This mines it STATICALLY from text the operator extracted from their OWN
installed app (decompiled APK/IPA strings, resources, manifest, plist) — no fetch and no
decompilation happen here (QL6/legal): it reads blobs you already hold, exactly as
js_extract reads JS you already fetched. SourceKind.MOBILE (T2).

It is the symmetric twin of the temporal differ: that one surfaces archived-only endpoints
(the time axis); this one surfaces mobile-only endpoints and off-web hosts (the client axis).
Both then feed existence_oracle (is it live?) → capture_plan (acquire it).

Deterministic (QL4). Mines & proposes, never adjudicates (QL5).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import SourceKind
from .js_extract import extract_endpoints

_URL = re.compile(r"https?://([A-Za-z0-9.\-]+(?::\d+)?)(/[^\s\"'<>\\)]*)?")
_STAGING = ("staging", "stage", "stg", "dev.", "-dev", "qa", "uat", "test.", "-test",
            "internal", "int.", "preprod", "pre-prod", "sandbox", "admin.", "api-internal")


@dataclass
class MobileSurfaceReport:
    endpoints: list = field(default_factory=list)
    hosts_main: set = field(default_factory=set)
    hosts_partner: set = field(default_factory=set)      # third-party / B2B client of the backend
    hosts_staging: set = field(default_factory=set)      # highest value: non-prod host reachable
    mobile_only: list = field(default_factory=list)      # keys absent from the web capture

    @property
    def summary(self) -> str:
        return (f"{len(self.endpoints)} endpoint(s); hosts main/{len(self.hosts_main)} "
                f"partner/{len(self.hosts_partner)} staging/{len(self.hosts_staging)}; "
                f"{len(self.mobile_only)} mobile-only")


def _classify_host(host: str, known_hosts) -> str:
    h = host.lower().split(":")[0]
    if any(s in h for s in _STAGING):
        return "staging"
    if known_hosts and any(h == k or h.endswith("." + k) or k.endswith("." + h) for k in known_hosts):
        return "main"
    return "partner"


def mine_mobile(blobs, *, known_hosts=None, web_keys=None) -> MobileSurfaceReport:
    """blobs: list of (text, locator) the operator extracted from their own app. `known_hosts`
    = the main in-scope hosts (to separate partner/staging from them). `web_keys` = endpoint
    keys already held from the web capture, to compute the mobile-only delta."""
    known = {h.lower() for h in (known_hosts or [])}
    web = set(web_keys or [])
    rep = MobileSurfaceReport()
    seen: dict = {}
    for text, loc in blobs:
        for m in _URL.finditer(text or ""):                       # (1) hosts from absolute URLs
            getattr(rep, f"hosts_{_classify_host(m.group(1), known)}").add(m.group(1).lower())
        for ep in extract_endpoints(text or "", loc, source=SourceKind.MOBILE):  # (2) paths+method
            if ep.key not in seen:
                seen[ep.key] = ep
                rep.endpoints.append(ep)
    rep.mobile_only = sorted(k for k in seen if k not in web)       # (3) client-axis delta
    for k in rep.mobile_only:
        seen[k].role_hints.append("mobile-only:absent-from-web")
    rep.endpoints.sort(key=lambda e: e.key)
    return rep
