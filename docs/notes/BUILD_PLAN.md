# IOLITE — Build Plan (senior-level)

## Goal (achievement test)
A deterministic, legal-by-construction recon engine that turns legally-captured
material (OSINT + your authenticated HAR + JS/sourcemaps + GraphQL/OpenAPI) into an
ONYX-compatible `spec.json` whose ranked probe set maximises authorization coverage
— with **zero** unauthorised requests and **zero** verdicts of its own.
Done when: `python -m iolite demo` runs offline and emits a `spec.json` that ONYX
`scan` accepts, plus a human dossier, plus a green test suite.

## Division of labour with ONYX (non-negotiable)
- IOLITE = surface **acquisition + modelling + ranking** (ONYX's stated gap).
- ONYX  = **Δstate confirmation** (the only verdict).
- Contract: the `spec.json` schema in `authpath/cli.py`. IOLITE emits exactly it.

## Phases
1. **Foundation** — models, Scope-Guard (QL1), ROE, provenance/evidence tiers. *(done)*
2. **Acquisition** — passive OSINT adapters (offline-capable), HAR ingest,
   JS + sourcemap miner, GraphQL + OpenAPI ingest.
3. **Depth axes** — temporal differ (ghost endpoints), id-format/enumerability.
4. **Modelling** — surface model (object graph · role matrix · endpoint catalog).
5. **Ranking** — deterministic authz-risk triage (transparent integer + reasons).
6. **Replay planning** — record-once → replay-as-N-principals (own principals only).
7. **Bridge** — emit ONYX `spec.json` + discovery contract; deterministic/sorted.
8. **Orchestration + CLI** — `pipeline.py`, `cli.py`, `__main__.py`.
9. **Verify** — unit tests (scope-guard, js-extract, triage, spec) + offline demo
   fixtures; run green.
10. **Package** — release tarball.

## Design rules (mirror ONYX discipline)
- Pure stdlib core; `requests`/`playwright` are opt-in extras for LIVE only.
- Every emitted artifact is deterministic (sorted keys, stable ordering).
- Every extracted fact carries provenance + an evidence tier.
- Scope-Guard fails safe: uncertainty ⇒ HALT.
- IOLITE never fabricates a principal, an id, or a finding.

## Roadmap beyond v0.1 (recorded, not built yet)
- Live passive adapters wired to `requests` (CT logs, wayback CDX, JS fetch).
- Playwright "record-once, replay-as-N" live driver with session hand-off.
- Scheduled continuous passive monitoring; surface-change diffing wakes the run.
- Mobile (APK/IPA) endpoint extractor.
- `agent_loop` hook: an analyst ranks hypotheses over the surface model; ONYX confirms.
