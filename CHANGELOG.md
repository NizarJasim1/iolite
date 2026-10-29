# Changelog

Short summary per release. The full notes, including measurements and the reasoning
behind each change, are in
[`docs/changelog-detail/DETAILED_RELEASE_NOTES.md`](docs/changelog-detail/DETAILED_RELEASE_NOTES.md).

## 1.29.0
- `reason --acquire` composes the acquisition modules into one pass: identity and
  gateway modelling with ranked pressure points, endpoints from your own mobile
  build, risk-ranked ghost endpoints, fail-closed existence checks on hidden
  siblings, and a capture plan for what to record next.
- A finding confirmed by ONYX re-weights discovery toward its neighbourhood.
- Off by default, so existing specs stay byte-identical.
  ([details](docs/changelog-detail/ACQUISITION_CHAIN.md))

## 1.28.0
- `iolite sim`: synthetic readiness run against modelled defences (rate limits,
  WAF and bot walls, challenges, token expiry) on a virtual clock. No real traffic.

## 1.22.0 – 1.27.0
- Live dashboard served by `iolite watch`: feed, learned policy table, relation
  graph and principal view, updated as you browse.
- One-click intervention config for the write path.
- The console dashboard made interactive (draggable, physical, keyboard and
  reduced-motion friendly) without changing its layout.

## 1.21.0
- Parallel execution of confirmation tasks, with a global rate limit held by the
  pacer, wired into the live confirmer.

## 1.20.0
- Defence awareness: rate limits, WAF and bot blocks and challenges are classified
  separately from real authorization denials, so a block never teaches the model a
  false boundary. Pacing adapts to the fastest rate the target tolerates.

## 1.19.0
- Full response reading (nested objects, collections, enumerable ids).
- Intent learned from contrast: what one account is allowed vs. what another is denied.

## 1.18.0
- `iolite watch`: build the intent model and confirm cross-account exposure while
  you browse, through a local collector. Still passive.

## 1.17.0
- `iolite hunt`: real multi-account captures in, offline-confirmed issues and a
  submittable dossier out. HAR ingest keeps response bodies.

## 1.16.0
- Offline corroboration that can close a bug without sending requests.
- Field-name-agnostic intent lattice (no hardcoded English vocabulary).
- Practical GraphQL techniques for large targets.

## 1.15.0
- Intent kill-chain wired to the real surface model, with a relational
  authorization lattice and wider divergence generation.

## 1.12.0 – 1.14.0
- New `iolite.intent` engine: reconstruct intended access by creating your own
  objects through the app, confirm the write side with reversible mutations, and
  separate cause from noise.
- Equivalence-class reduction for scale (test representatives, not instances).
- One unified pipeline: generate → reduce → schedule → confirm → certify → report.

## 1.11.0
- Fail-closed live gateway: preflight checks (attestation, scope, two own
  principals, non-destructive, rate governor, ONYX reachable) before any packet.

## 1.10.0
- IntentGraph: least-privilege intent reconstruction across the whole surface.
- Expected-value layer for deciding what to submit and where to spend time.

## 1.9.0
- Workflow guards mined from the frontend (state enums, status checks) become
  gate-skip hypotheses.
- Deeper, obfuscation-resistant surface recovery from client code.

## 1.6.0 – 1.6.1
- Research scoring tied to concrete pipeline paths, risk-adjusted, with a ledger
  for spotting uncrowded programs.
- The ONYX tab in the control center loads reliably.

## 1.5.0
- `iolite research`: rank public bug-bounty programs by fit for this toolchain.

## 1.0.0 – 1.4.0
- Control center (`iolite serve`) driving the real pipeline, with an embedded ONYX tab.
- `iolite go`: point at a folder of captures, build, verify with ONYX.
- Own visual identity. Renamed from QUARRY to IOLITE.

## 0.1.0 – 0.7.0
- Initial engine: scope guard, passive OSINT, HAR, JS, sourcemap, GraphQL and
  OpenAPI ingest, ghost-endpoint diff, surface model, risk triage, replay planner,
  ONYX spec bridge.
- JS miner with measured recall and precision (`iolite selftest`).
- Object ids from every carrier: path, query, headers, JWT claims, GraphQL
  variables, body.
- Hardened scope guard (wildcards, exclusions, homograph and userinfo tricks).
- Fair probe budget; only probeable endpoints go into the contract.
- Caps for hostile or oversized input, and a golden snapshot for byte-stable output.
