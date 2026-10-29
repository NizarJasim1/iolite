# Acquisition and feedback chain (v1.29.0)

All modules below are **additive** (no existing behaviour changed, except one root-cause
robustness fix). Green gate: **383 passed / 0 failed**. Design laws held throughout:
QL4 deterministic · QL5 proposes-only (ONYX confirms by Δstate) · QL6 own-scope/legal.

Each pair closes two sides of ONE boundary ("seam"), so combining them adds precision.

## Pair 4 — the enforcement/identity boundary
- `iolite/intent/federation.py` — mines the identity surface from legal evidence: OIDC/OAuth
  endpoints, provider+protocol inferred from a decoded JWT, identity claims, and ROE-gated
  leads (audience-confusion, cross-tenant `sub`) as propose-only hypotheses. Passive; no fetch.
- `iolite/intent/architecture.py` — models topology (gateway / BFF / direct) and the authz
  pattern (ReBAC/RBAC) from lattice fields, folds in identity, and emits ranked **pressure
  points** for ONYX (sharpest: a type bound both under and over the gateway → "test the
  service layer, not the gateway").

## Pair 5 — test-surface completeness / the acquisition frontier
- `iolite/intent/existence_oracle.py` — discovers the **hidden** surface: hypothesises
  unobserved siblings from observed path structure (version bump, `/admin//internal/`,
  collection↔item), then confirms **existence only**, **fail-closed** (no attestation /
  automation / scope ⇒ nothing sent, leads returned), SAFE methods (HEAD/OPTIONS/GET),
  rate-limited, distinguishing 404 (absent) from 401/403 (exists & protected) / 405 / 2xx.
- `iolite/intent/capture_plan.py` — turns `reason.coverage` gaps into a **prioritised capture
  plan**: per object type, which missing flow, how many accounts, ranked by the authz tests
  it unlocks (read/action BOLA, BOPLA, rebinding, tenant). Existence-oracle hits fold in on top.

## Pair 6 — surface beyond the web capture
- `iolite/mobile_mine.py` (client axis) — statically mines the operator's own extracted
  mobile/partner binary for hosts and paths the web bundle never ships; classifies off-web
  hosts (partner / staging-internal) and computes the **mobile-only delta** vs the web keyset.
- `iolite/reason/ghost_triage.py` (time axis) — widens `temporal_diff` to the Wayback/gau URL
  feed, then **ranks ghosts by authz-risk** (privilege, object-id, write) and flags version
  **auth-regression** (ghost v1 under live v2). Emits probe paths → existence_oracle.

## Pair 7 — the adaptive loop (chain closed)
- `iolite/reason/feedback.py` — a **confirmed** ONYX finding re-weights discovery and capture
  toward its neighbourhood (same object-type, version family, privileged prefix, host, write
  verb). Writes into triage's own transparent ledger (`ep.risk` + "+N reason"), **bounded by a
  cap**, re-orders only — ONYX still confirms each by Δstate.

## Root-cause robustness fix
- `iolite/pipeline.py` + `iolite/limits.py` — the deep-JSON guard never fired because the C
  json scanner parses thousands of levels without erroring. Added `MAX_JSON_DEPTH` and an
  O(n), string-aware depth pre-check in `_safe_json`: a pathological file is now skipped with
  a note instead of silently parsed. (Closed the last failing test → fully green.)

## Flow
web + mobile/partner (space) + ranked archive (time) + hidden (existence oracle)
→ `capture_plan` → ONYX confirms (Δstate) → `feedback` re-weights → next pass.

## v1.29.0 — chain INTEGRATED into the engine (was: modules existed but nothing called them)
Until now `architecture`, `mobile_mine`, `ghost_triage` and `feedback` were reachable only
from their unit tests — not from `reason()` or the CLI, so an operator run never exercised
them. This release composes the whole chain into one opt-in pass, additive and byte-identical
by default:
- `reason/engine.py` — new `run_acquisition()` + `AcquisitionReport`, and a `with_acquisition`
  path on `reason()`. It builds the lattice, mines the federation/identity surface, models the
  architecture (→ ranked pressure points), folds the mobile-only surface into the live model,
  authz-ranks archived ghosts (incl. a raw Wayback/gau URL feed), turns hidden siblings +
  top ghosts into existence-oracle probes (fail-closed under ROE), emits the coverage-guided
  capture plan, and — when prior ONYX verdicts are supplied — runs the `feedback` loop over
  discovery + capture. All results surface under `spec._reason.acquisition`; nothing is
  emitted unless the pass runs, so the default spec is unchanged (verified: identical
  `candidates`).
- `reason/engine.py` — `reason()` default is preserved exactly; the pass runs only on
  `--acquire` / mobile / archived-urls / confirmed-findings. `__reason_version__ → 0.14.0`.
- `cli.py` — `reason` gains `--acquire` and `--archived-urls FILE`; with `--cegar`/`--kb`,
  each CONFIRMED finding re-weights the acquisition discovery+capture for the next pass
  (loop closed end-to-end). Prints a compact acquisition summary.
- `reason/__init__.py` — exports `run_acquisition`, `AcquisitionReport`, and (lazily, to
  avoid the relation_model↔reason import cycle) the `feedback` helpers.
Green gate held: **383 passed / 0 failed**. QL4 (deterministic) · QL5 (proposes-only; ONYX
confirms by Δstate) · QL6 (own-scope/legal; hidden paths confirmed for EXISTENCE only,
fail-closed) — all preserved. No existing behaviour changed.
