# IOLITE — Architecture

**IOLITE is the legal deep authorization-surface acquisition engine — the recon
companion that feeds ONYX/AuthPath.**

ONYX is the *prover*: it confirms an authorization break by a Δstate read-back and
refuses to guess (zero false positives, by construction). ONYX's own
`discovery.py` states its honest boundary verbatim:

> *"this finds DECLARED endpoints. Hidden/undocumented endpoints need JS/source-map
> mining + fuzzing (noisier, separate) — not claimed here."*

**IOLITE is exactly that missing half.** It mines the deepest surface a target
*legally* exposes, models it, ranks it by authorization risk, and emits an
ONYX-compatible `spec.json`. It never decides truth — ONYX still does, by Δstate.
That division is the whole design: **IOLITE acquires, ONYX confirms.**

---

## The load-bearing invariants (mirrored from ONYX)

| # | Invariant | Where it lives |
|---|-----------|----------------|
| **QL1** | **Legal-by-construction.** Every request-emitting stage passes the Scope-Guard; anything outside the declared, authorised scope resolves to *do nothing*. | `scope_guard.py`, `roe.py` |
| **QL2** | **Passive-first.** Zero-touch OSINT and offline analysis of already-captured material run before any request touches the target. Live stages are opt-in and human-paced. | `passive.py`, `pipeline.py` |
| **QL3** | **Provenance on every fact.** Every extracted endpoint/param/role carries its source and an evidence tier — nothing is asserted without saying where it came from. | `provenance.py` |
| **QL4** | **Deterministic.** No ML, no learned baseline; extraction is parse + regex + table lookup; the same inputs always produce the same `spec.json` (byte-stable, sorted). | all modules |
| **QL5** | **Acquire, never adjudicate.** IOLITE only proposes *what* to test; it cannot create a finding. ONYX's Δstate confirmer has the only verdict. | `onyx_spec.py` |
| **QL6** | **Own-principals only.** Cross-principal probes are planned strictly between principals the operator controls — never against a real third party's data. | `replay.py`, `onyx_spec.py` |

A wrong extraction can only ever cause *more* to be tested (a candidate ONYX will
drop), never an unauthorised request (Scope-Guard) and never a fabricated finding
(ONYX owns the verdict).

---

## The pipeline

```
        ┌─ ⓪ Scope-Guard ───── legal boundary, fail-safe to inaction (QL1)
        │
inputs  ┤  ① Passive acquire ── zero-touch OSINT: CT logs, wayback/gau, GitHub  (QL2)
(legal) │  ② Session bridge ─── authenticated multi-principal HAR (your accounts)
        │  ③ Surface extract ── JS + sourcemaps + GraphQL schema + OpenAPI
        │  ④ Temporal differ ── current vs archived JS → "ghost" endpoints
        │  ⑤ Surface model ──── object graph · role matrix · id-format · catalog
        │  ⑥ Authz-risk triage  deterministic integer score + reasons (budgeted)
        │  ⑦ Replay planner ─── record-once → replay-as-N-principals (own principals)
        └─ ⑧ ONYX bridge ────── emit spec.json (principals · contract · seed · probe)
                                        │
                                        ▼
                              ONYX `scan spec.json`  →  Δstate-confirmed findings
```

## The three depth axes (IOLITE's unfair advantage — all legal)

- **Time axis** (`temporal_diff.py`): archived vs current JS/URLs surface
  *ghost endpoints* — removed from the frontend, still live on the backend — where
  authorization rots. Maps to ONYX `TEMPORAL_DRIFT` / `AUTH_REGRESSION`.
- **Client axis** (`surface_model.py`): web BFF vs mobile BFF vs partner API often
  enforce authz inconsistently; capturing all clients and diffing them feeds ONYX
  `CROSS_SURFACE`.
- **Principal axis** (`har_ingest.py`, `replay.py`): the same action captured as
  several accounts *you own* is the raw material for BOLA/BFLA — proven by Δstate
  between principals you control.

## Module map

| File | Component |
|------|-----------|
| `iolite/models.py` | shared deterministic data types + `Provenance` / evidence tiers (QL3) |
| `iolite/normalize.py` | path→`{id}` templating + object-id recognition (matches ONYX `endpoint_key`) |
| `iolite/scope_guard.py` | ⓪ Scope-Guard (QL1, fail-safe) |
| `iolite/roe.py` | rules-of-engagement / the legal ceiling, enforced |
| `iolite/passive.py` | ① zero-touch OSINT adapters (offline-capable) |
| `iolite/har_ingest.py` | ② HAR → per-principal exchanges |
| `iolite/js_extract.py` | ③ JS endpoint/param/role/flag miner |
| `iolite/sourcemap.py` | ③ `.js.map` → source tree + richer mining |
| `iolite/graphql_schema.py` | ③ GraphQL introspection → endpoints |
| `iolite/openapi_ingest.py` | ③ OpenAPI/Swagger → endpoints |
| `iolite/temporal_diff.py` | ④ ghost-endpoint differ |
| `iolite/idformat.py` | id shape + enumerability classifier |
| `iolite/surface_model.py` | ⑤ object graph · role matrix · catalog |
| `iolite/triage.py` | ⑥ deterministic authz-risk scoring |
| `iolite/replay.py` | ⑦ record-once → replay-as-N-principals plan |
| `iolite/carriers.py` | object-id extraction across path/query/header/JWT/GraphQL/body |
| `iolite/onyx_spec.py` | ⑧ emit ONYX-compatible `spec.json` (tier-aware; contract vs leads) |
| `iolite/triage.py` | ⑥ deterministic authz-risk scoring |
| `iolite/replay.py` | ⑦ record-once → replay-as-N (horizontal + vertical, fair budget) |
| `iolite/calibrate.py` | measured extraction recall/precision (`iolite selftest`) |
| `iolite/limits.py` | resource caps (hostile/huge/malformed input defence) |
| `iolite/pipeline.py` | orchestrator (acquire → model → triage → emit; graceful skips) |
| `iolite/report.py` | deterministic human surface dossier |
| `iolite/serve.py` + `dashboard/index.html` | the purple control center (HUD → ONYX) |
| `iolite/cli.py` | `python -m iolite ...` |

## What IOLITE is NOT

- Not a discovery tool for **injection/SSRF/XSS** — those are out of ONYX's arena,
  so out of IOLITE's.
- Not a WAF-evasion or high-volume fuzzer — QL2/QL1 forbid it. Depth comes from
  *legal breadth of sources*, not from out-muscling defences.
- Not a decision engine — QL5. It hands ONYX a richer, ranked surface; ONYX judges.
