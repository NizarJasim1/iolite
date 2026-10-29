# REASON ENGINE — Build Protocol & Hard Rules (v0.1)

> The goal: a **grey-box authorization reasoning
> engine** inside IOLITE that reconstructs the developer's **intended** access
> policy (I), measures the **enforced** policy (E), and hunts **I △ E** — plus
> violations of **transplanted invariants** and **negated developer assumptions** —
> surfacing deep, cross-surface, compositional authz Criticals that neither the
> developer (sees only intent) nor a scanner (sees only patterns) can see.
> **ONYX proves every candidate by Δstate. Never weaken IOLITE or ONYX.**

This engine is a **candidate/hypothesis generator**. It NEVER decides a finding.
It PROPOSES; ONYX DISPOSES. That is not a slogan — it is enforced by the fact that
`reason` emits only `ReasonCandidate`s that become ONYX `probe` items, and holds
no verdict field.

## The eight hard rules (a change that breaks any of these is rejected)

- **P1 — Additive-only.** New code lives under `iolite/reason/`. **Zero edits to
  ONYX (`authpath/*`), ever.** The only edits to existing IOLITE are additive:
  register one `reason` subcommand in `cli.py`, bump `__version__`, add a
  changelog. No existing module's behavior changes. No existing test changes.

- **P2 — Green gate.** The full suite (`ONYX_PATH=… python3 tests/run_all.py`) is
  run **before and after** every change and must stay **≥ 102 passed, 0 failed**.
  New tests only add to the count. A red suite reverts the change.

- **P3 — Legal-by-construction (inherits QL1–QL6).** `reason` consumes only the
  already-acquired `SurfaceModel` + the `Engagement`. It sends **no packets**. Live
  confirmation happens only through ONYX, only under a real attestation
  (`Engagement.attested()`), with `dry_run` gating unchanged. Cross-principal
  candidates only ever ask **your own principals** to reach objects (QL6).

- **P4 — Acquire-never-adjudicate (QL5) = the one-way rule.** `reason` emits
  candidates with provenance + confidence + the **ONYX EffectClass** each will be
  confirmed under. It emits **no verdicts**. The interface to ONYX is one-way:
  reason → candidate spec → ONYX → Δstate verdict.

- **P5 — Determinism (QL4).** Sorted outputs, stable ordering, no randomness, no
  wall-clock in logic. Golden-testable.

- **P6 — Provenance (QL3).** Every intent rule and every candidate cites its
  evidence source(s), tier, and a one-line human-checkable rationale.

- **P7 — Honesty ceiling embedded.** The engine records the named walls in its
  output (undecidability ⇒ bounded depth k, no completeness; reconstruction ⇒
  bounded by observed surface). Coverage/confidence is never inflated. A capability
  not built is listed as `planned`, produces zero candidates, and is never claimed.

- **P8 — One-directional dependency.** `iolite/reason/*` imports from
  `iolite.models / surface_model / replay / onyx_spec / roe / scope_guard /
  normalize / idformat / carriers / triage` (read-only consumers). **Nothing in
  `iolite/` imports `reason`** except the lazy handler inside `cli.py`.

## Build order (execution budget — no boiling the ocean)

1. **Seed (this cut):** `intent` → `enforcement` → `differ` (I△E) → one real
   `invariant` (CrossSurfaceConsistency) → one real `assumption`
   (UnguessableIds) → `engine` (emits enriched ONYX spec) → `report`. Tests +
   green gate + tarball.
2. Grow the invariant catalog (non-interference/side-channel, conservation,
   freshness, information-flow) one at a time, each: implement → test → green gate.
3. Grow the assumption library (HAZOP) one at a time, same gate.
4. Bounded global search (CEGAR loop with ONYX as oracle) — only after the
   catalog proves value on a real target.

Every promotion from `planned` to implemented passes P1–P8 and the green gate.
