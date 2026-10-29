# WALL-5 — state ledger

**Version:** 1.15.0   **Status:** wired, green (official suite 239/1 — the 1 is the
pre-existing env-only `test_deeply_nested_json_skipped`, identical on 1.11/1.14).

## Delivered
- [x] `relation_model.py` — relational authorization lattice (Zanzibar-shaped) built
      from the real `SurfaceModel`; one `intended_decision` derivation over
      principal × action × object × field × state × tenant. Raise-only / least-privilege.
- [x] `divergence.py` — wide enumerator, 8 families (5 are scanner blind spots), each
      candidate carrying its intent-deny derivation. PROPOSE-only.
- [x] `metamorphic.py` — the one sound oracle (MR_authz + FP filters + Wall-3 write
      safety). FP=0 by construction; replayable certificate.
- [x] `kill_chain.py` — WIRED GENERATE→REDUCE→SCHEDULE→CONFIRM→CERTIFY→REPORT on a real
      model; pluggable confirmer (offline honest LEADs / live ONYX).
- [x] CLI: `python3 -m iolite.intent killchain`.
- [x] 38 new `test_*` assertions across 4 files, discovered by `run_all.py`
      (201 → 239). Fixes v1.14's "tests not in the suite".

## Evidence (in-model capture)
36 raw → 15 equivalence reps; 7 families generated from an ACTUAL SurfaceModel (not
hardcoded); irreversible delete REFUSED; FP=0. With a simulated live confirmer the
scanner-blind families CONFIRM at FP=0, each with a replayable certificate; a benign
world confirms nothing (FP floor).

## Remaining (honest floor)
- [ ] Field T1 run against an authorized live program (VAmPI/crAPI first, then scope).
- [ ] Matched no-relationship control provisioning for live causal falsification.
- [ ] Chained recall is bounded by observed id-disclosure; add response-id correlation
      from live captures.
- [ ] Concurrency/TOCTOU and deep-GraphQL (alias/batch) generators.
- [ ] Fold the lattice back into `iolite.reason` as the intent core (de-dupe with
      `intent_graph`).
