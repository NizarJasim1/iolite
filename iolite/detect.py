"""
Directory auto-detection — point IOLITE at a folder, not a flag soup.

Classifies every file in a captures directory into the right Inputs slot, by
extension and a small JSON peek, so a non-expert runs one command:

    iolite go --dir ./captures

Rules (deterministic, sorted):
  *.har                              → har_files (authenticated captures)
  *.js.map / *.map                   → sourcemap_files
  *.js / *.mjs                       → js_files, OR archived_js_files if the path
                                       says so (archive/archived/wayback/old/history)
  *.json  →  peek:
        has "log.entries"            → har_files (HAR saved as .json)
        has "__schema" / data.__schema → graphql_file (introspection)
        has "paths" or "swagger"/"openapi" → openapi_file
        name looks like roe/engagement → engagement (returned separately)
Unknown files are ignored (recorded as a note).
"""

from __future__ import annotations

import json
import os

from .pipeline import Inputs

_ARCHIVE_HINT = ("archive", "archived", "wayback", "/old", "old_", "history", "snapshot")


def _peek_json(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.loads(fh.read(2_000_000))
    except Exception:
        return None


def _is_archived(path: str) -> bool:
    p = path.lower()
    return any(h in p for h in _ARCHIVE_HINT)


def _looks_roe(name: str) -> bool:
    n = name.lower()
    return ("engagement" in n or n.startswith("roe") or n == "roe.json"
            or "rules_of_engagement" in n)


def detect_dir(root: str) -> tuple[Inputs, str | None, list[str]]:
    """Return (Inputs, engagement_path_or_None, notes). Walks `root` recursively."""
    inp = Inputs()
    engagement_path = None
    notes: list[str] = []
    if not os.path.isdir(root):
        return inp, None, [f"{root}: not a directory"]

    files = []
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            files.append(os.path.join(dirpath, n))
    files.sort()

    for path in files:
        low = path.lower()
        if low.endswith((".js.map", ".map")):
            inp.sourcemap_files.append(path)
        elif low.endswith(".har"):
            inp.har_files.append(path)
        elif low.endswith((".js", ".mjs")):
            (inp.archived_js_files if _is_archived(path) else inp.js_files).append(path)
        elif low.endswith(".json"):
            name = os.path.basename(path)
            if _looks_roe(name):
                engagement_path = engagement_path or path
                continue
            doc = _peek_json(path)
            if not isinstance(doc, dict):
                notes.append(f"ignored {name}: unrecognised JSON")
                continue
            if isinstance(doc.get("log"), dict) and "entries" in doc["log"]:
                inp.har_files.append(path)
            elif "__schema" in doc or (isinstance(doc.get("data"), dict) and "__schema" in doc["data"]):
                inp.graphql_file = inp.graphql_file or path
            elif "paths" in doc or "swagger" in doc or "openapi" in doc:
                inp.openapi_file = inp.openapi_file or path
            else:
                notes.append(f"ignored {name}: JSON but not HAR/GraphQL/OpenAPI/ROE")
        else:
            notes.append(f"ignored {os.path.basename(path)}: unsupported type")

    # stable ordering
    inp.har_files.sort(); inp.js_files.sort()
    inp.sourcemap_files.sort(); inp.archived_js_files.sort()
    return inp, engagement_path, notes


def summarize(inp: Inputs) -> str:
    return (f"{len(inp.har_files)} HAR · {len(inp.js_files)} JS · "
            f"{len(inp.sourcemap_files)} sourcemap · {len(inp.archived_js_files)} archived · "
            f"graphql={'yes' if inp.graphql_file else 'no'} · "
            f"openapi={'yes' if inp.openapi_file else 'no'}")
