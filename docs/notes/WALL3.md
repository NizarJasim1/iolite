# Wall-3 — safe mutation: confirming the write side without harm

## The wall
To confirm a write-side authorization break (the ~42% action-level majority:
account takeover, fund transfer, data destruction) you MUST cause a real state
change (RL3: no Δstate, no finding). But writes can be irreversible, hit a real
third party, or fire external effects — which the fail-safe (RL5) forbids by
default. So the safety rail blinds the engine to the biggest, highest-impact class.

## The breakthroughs
1. **Refined fail-safe:** suppress only *provably-unsafe* mutations, not all.
2. **Empirical reversibility rehearsal** (`wall3_sweep.py`): don't assume
   reversibility (undecidable on a black box) — MEASURE it on a SACRIFICIAL object
   we own (apply → attempt inverse → verify exact restoration → watch OOB). Only
   ops that empirically revert with no external effect are used.
3. **Three-gate defense** (a flaw the running kernel exposed — rehearsing an
   external op *causes* its effect): **static screen (non-executing: danger
   keywords + operator allowlist) → empirical rehearsal → write-ahead saga.**
4. **Full write-surface sweep** across the taxonomy: write-BOLA, BOPLA-write
   (mass-assignment), delete-BOLA — budgeted, auto-cleanup of every test object
   (closes the Wall-1 deferred cleanup), transparent mutation ledger.
5. **Durable (on-disk) WAL** (`wall3_saga.py`): every mutation's compensating
   delete is written to disk *before* the mutation; a crash is recovered by a
   fresh process replaying the WAL over HTTP → net-zero even across a crash.

## Verified on an INDEPENDENT target (VAmPI) — honest finding
VAmPI has **no true write-BOLA** (verified from source: `PUT …/email` is
self-scoped to the token user; `DELETE …/{username}` is admin-gated; books have
no update). It **does** have a real write-side authz bug: `POST /users/v1/register`
honours an `admin` field → **self-provisioned admin (mass-assignment / BOPLA-write
/ privilege escalation).** `wall3_saga.py` confirms it live:
- gate0 screen → gate1 rehearsal (create↔delete reversible, no external effect)
- confirm by **non-destructive** Δstate read-back: `attacker.admin=True` vs
  `control.admin=False` (the `/users/v1/_debug` differential)
- durable WAL protects the created users; cleanup leaves **net-zero** (no test
  users remain); a simulated crash is recovered from the on-disk WAL.
Run log: `docs/wall3_evidence/vampi_write_run.txt`.

## What is NOT solved (honest, deferred)
- **Side-effect classification is undecidable** on a black box. The static screen
  is keyword-heuristic (false-pass possible) and the allowlist + operator
  assertion is the irreducible human gate for external effects. Highest-risk
  categories must be allowlisted explicitly or they never run.
- **Rehearsal is strong evidence, not proof** (data/state-dependence); the saga's
  verify-restore + loud HALT is the backstop, and needs optimistic-concurrency
  against row drift.
- **Idempotency** (retried mutation double-apply), **state-gated writes**
  (sequence-dependent), and **concurrency/TOCTOU** writes are not covered.
- The saga adapters are VAmPI-specific; generalization to OpenAPI-declared
  mutating ops is the integration step (toward `iolite.reason`).

## Verdict
Wall-3's safe-mutation core is designed, hardened by a found flaw, and **confirmed
on independent code with net-zero harm + durable crash recovery**. Not absolute
closure: side-effect classification stays an allowlist-gated human judgment.
