"""
④ Temporal differ — the ghost-endpoint axis.

Highest-ROI legal technique: endpoints that appear in ARCHIVED JS (Wayback /
CommonCrawl) but are gone from the CURRENT bundle frequently remain live on the
backend, where the authorization check was quietly dropped when the UI moved on.
These map to ONYX `TEMPORAL_DRIFT` / `AUTH_REGRESSION`.

Deterministic set difference over mined endpoint keys. No network (operates on JS
blobs you already fetched, current and archived).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Endpoint, Provenance, SourceKind
from .js_extract import extract_endpoints


@dataclass
class GhostReport:
    ghosts: list[Endpoint] = field(default_factory=list)   # in archived, not current
    current_keys: set[str] = field(default_factory=set)
    archived_keys: set[str] = field(default_factory=set)

    @property
    def summary(self) -> str:
        return (f"{len(self.ghosts)} ghost endpoint(s) "
                f"({len(self.archived_keys)} archived vs {len(self.current_keys)} current)")


def diff(current_js: list[tuple[str, str]],
         archived_js: list[tuple[str, str]]) -> GhostReport:
    """current_js / archived_js are lists of (text, locator)."""
    cur: dict[str, Endpoint] = {}
    for text, loc in current_js:
        for ep in extract_endpoints(text, loc, source=SourceKind.JS):
            cur.setdefault(ep.key, ep)
    arch: dict[str, Endpoint] = {}
    for text, loc in archived_js:
        for ep in extract_endpoints(text, loc, source=SourceKind.ARCHIVED_JS):
            arch.setdefault(ep.key, ep)

    rep = GhostReport(current_keys=set(cur), archived_keys=set(arch))
    for key in sorted(set(arch) - set(cur)):
        ep = arch[key]
        ep.role_hints.append("ghost:removed-from-current-ui")
        ep.provenance.append(Provenance.of(
            SourceKind.ARCHIVED_JS, key,
            note="present in archived bundle, absent from current — verify still live"))
        rep.ghosts.append(ep)
    return rep
