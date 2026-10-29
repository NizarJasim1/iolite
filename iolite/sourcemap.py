"""
③ Sourcemap (`.js.map`) reader — the richest legal frontend source.

A published `.js.map` embeds the original source tree (`sources`) and, very often,
the original source text (`sourcesContent`) with real variable names, route
tables, and role checks intact. Mining `sourcesContent` yields far cleaner endpoint
and role signal than minified bundles.

Pure stdlib JSON parse; no execution. Endpoints carry SOURCEMAP provenance.
"""

from __future__ import annotations

import json

from .models import Endpoint, SourceKind
from .js_extract import extract_endpoints, extract_flags
from .limits import MAX_SOURCES, MAX_SOURCE_BYTES


def parse_sourcemap(text: str, locator: str) -> tuple[list[Endpoint], list[str], list[str]]:
    """Return (endpoints, source_paths, feature_flags) from a .js.map blob.

    Tolerant: a map with no `sourcesContent` still yields its `sources` tree
    (useful surface-structure signal) but no code to mine.
    """
    try:
        data = json.loads(text)
    except Exception:
        return [], [], []
    if not isinstance(data, dict):
        return [], [], []

    sources = [s for s in (data.get("sources") or []) if isinstance(s, str)][:MAX_SOURCES]
    contents = data.get("sourcesContent") or []
    endpoints: dict[str, Endpoint] = {}
    flags: set[str] = set()

    for i, src in enumerate(sources):
        code = contents[i] if i < len(contents) and isinstance(contents[i], str) else ""
        if not code:
            continue
        if len(code) > MAX_SOURCE_BYTES:
            code = code[:MAX_SOURCE_BYTES]
        # skip third-party noise; focus on the app's own sources
        low = src.lower()
        if "node_modules" in low or low.endswith((".css", ".scss", ".less")):
            continue
        loc = f"{locator}:{src}"
        for ep in extract_endpoints(code, loc, source=SourceKind.SOURCEMAP):
            if ep.key in endpoints:
                endpoints[ep.key].merge(ep)
            else:
                endpoints[ep.key] = ep
        for f in extract_flags(code):
            flags.add(f)

    app_sources = sorted(s for s in sources if "node_modules" not in s.lower())
    return ([endpoints[k] for k in sorted(endpoints)], app_sources, sorted(flags))
