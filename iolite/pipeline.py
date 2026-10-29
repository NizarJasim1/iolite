"""
Orchestrator — acquire → model → triage → plan → emit.

Deterministic end-to-end. Reads only files you already captured (QL2); the only
network is an explicit opt-in live acquisition, out of scope for this function.
Everything is filtered by the Scope-Guard (QL1) and carries provenance (QL3).
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass, field

from . import js_extract, sourcemap, graphql_schema, openapi_ingest, temporal_diff
from . import surface_model, triage, replay, onyx_spec, report
from .har_ingest import ingest_har
from .models import SurfaceModel
from .roe import Engagement
from .scope_guard import ScopeGuard


@dataclass
class Inputs:
    har_files: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    sourcemap_files: list[str] = field(default_factory=list)
    archived_js_files: list[str] = field(default_factory=list)
    graphql_file: str = ""
    openapi_file: str = ""
    base_url: str = ""
    max_probes: int = 500
    runtime_files: list[str] = field(default_factory=list)   # Point 2: runtime-hook logs


@dataclass
class Result:
    model: SurfaceModel
    plan: replay.ReplayPlan
    spec: dict
    dossier: str
    ghost: temporal_diff.GhostReport
    flags: list[str] = field(default_factory=list)


def _read(path: str) -> str:
    from .limits import MAX_INPUT_BYTES
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read(MAX_INPUT_BYTES + 1)[:MAX_INPUT_BYTES]


def _json_depth(s: str) -> int:
    """Max bracket-nesting depth, string-aware (brackets inside JSON strings don't count).
    O(n), no recursion — the C json scanner accepts thousands of levels without erroring,
    so depth must be bounded BEFORE parse."""
    depth = mx = 0
    instr = esc = False
    for c in s:
        if instr:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                instr = False
            continue
        if c == '"':
            instr = True
        elif c in "[{":
            depth += 1
            if depth > mx:
                mx = depth
        elif c in "]}":
            depth -= 1
    return mx


def _safe_json(path: str, notes: list) -> dict | None:
    """Parse JSON, degrading gracefully: a missing/malformed/oversized/too-deep file
    is SKIPPED with a note, never crashing the whole run (QL2 robustness)."""
    try:
        raw = _read(path)
        from .limits import MAX_JSON_DEPTH
        if _json_depth(raw) > MAX_JSON_DEPTH:
            notes.append(f"skipped {path}: malformed or too-deeply-nested JSON")
            return None
        data = json.loads(raw)
        return data if isinstance(data, (dict, list)) else None
    except FileNotFoundError:
        notes.append(f"skipped {path}: file not found")
    except (ValueError, RecursionError):
        notes.append(f"skipped {path}: malformed or too-deeply-nested JSON")
    except OSError as e:
        notes.append(f"skipped {path}: {type(e).__name__}")
    return None


def run(engagement: Engagement, inputs: Inputs, redact: bool = True,
        deep: bool = False) -> Result:
    scope = engagement.scope_config()
    guard = ScopeGuard(scope)
    model = SurfaceModel(base_url=inputs.base_url)

    # ② HAR — authenticated multi-principal capture. Principals get stable pids A,B,C.
    # A malformed HAR is skipped with a note (and does NOT consume a principal id).
    pids = iter(string.ascii_uppercase)
    host_counts: dict[str, int] = {}
    for path in inputs.har_files:
        har = _safe_json(path, model.notes)
        if har is None:
            continue
        label = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        pid = next(pids, label)
        res = ingest_har(har, label, guard, pid=pid)
        model.principals.append(res.principal)
        surface_model.merge_endpoints(model, res.endpoints)
        for acc in res.accesses:
            model.add_access(acc)
        for h, c in res.hosts.items():
            host_counts[h] = host_counts.get(h, 0) + c
            model.hosts_seen.add(h)

    # pick host/base_url from the most-frequent in-scope host if not given
    if not model.host and host_counts:
        model.host = max(host_counts, key=host_counts.get)
    if not model.base_url and model.host:
        model.base_url = f"https://{model.host}"

    def _safe_text(path: str) -> str:
        try:
            return _read(path)
        except OSError as e:
            model.notes.append(f"skipped {path}: {type(e).__name__}")
            return ""

    # ③ JS bundles (current)
    current_js: list[tuple[str, str]] = []
    for path in inputs.js_files:
        text = _safe_text(path)
        if not text:
            continue
        current_js.append((text, path))
        surface_model.merge_endpoints(model, js_extract.extract_endpoints(text, path))

    # ③ sourcemaps (richest)
    flags: set[str] = set()
    for path in inputs.sourcemap_files:
        text = _safe_text(path)
        if not text:
            continue
        eps, _sources, sm_flags = sourcemap.parse_sourcemap(text, path)
        surface_model.merge_endpoints(model, eps)
        flags.update(sm_flags)

    # ③ GraphQL introspection
    if inputs.graphql_file:
        doc = _safe_json(inputs.graphql_file, model.notes)
        if doc is not None:
            surface_model.merge_endpoints(
                model, graphql_schema.parse_introspection(doc, inputs.graphql_file))
    # ③ OpenAPI
    if inputs.openapi_file:
        doc = _safe_json(inputs.openapi_file, model.notes)
        if doc is not None:
            surface_model.merge_endpoints(
                model, openapi_ingest.parse_openapi(doc, inputs.openapi_file))

    # ④ temporal diff — ghost endpoints (archived-only)
    archived_js = [(_safe_text(p), p) for p in inputs.archived_js_files]
    archived_js = [(t, p) for t, p in archived_js if t]
    ghost = temporal_diff.diff(current_js, archived_js)
    for ep in ghost.ghosts:
        model.add_endpoint(ep)
        model.ghost_keys.add(ep.key)

    # ④' DEEP acquisition (Point 2) — opt-in, additive. Recovers request-config
    # endpoints + client-derived GraphQL (introspection-independent) + runtime
    # self-disclosure (obfuscation-proof). Default OFF ⇒ surface byte-identical.
    if deep:
        from . import surface_ast, surface_runtime
        deep_pairs = current_js + archived_js
        surface_model.merge_endpoints(model, surface_ast.deep_recover(deep_pairs))
        for path in inputs.runtime_files:
            text = _safe_text(path)
            if not text:
                continue
            r_eps, r_accs = surface_runtime.ingest_runtime(text, path)
            surface_model.merge_endpoints(model, r_eps)
            for acc in r_accs:
                if acc.principal_id in {p.pid for p in model.principals}:
                    model.add_access(acc)      # own-principal accesses only (QL6)

    # ⑥ triage — deterministic authz-risk ranking
    triage.rank(model)

    # ⑦ replay plan (record-once → replay-as-N, own principals)
    plan = replay.build_plan(model, max_probes=inputs.max_probes)

    # ⑧ emit ONYX spec + dossier
    spec = onyx_spec.build_spec(model, plan, scope, engagement=engagement, redact=redact)
    dossier = report.render(model, plan, ghost, engagement, sorted(flags))

    return Result(model=model, plan=plan, spec=spec, dossier=dossier,
                  ghost=ghost, flags=sorted(flags))
