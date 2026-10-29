# WALL-11 — parallel execution + the wired live confirmer

> The capstone: wire the defense-aware executor into the confirmer and parallelize, so the
> EV-ranked leads are confirmed at the fastest pace a hardened target tolerates. The chain now
> runs end to end: GENERATE → SCHEDULE → EXECUTE (parallel, paced, defence-aware) → DISPOSE
> (value-presence) → DOSSIER.

## Parallel execution (`executor.run_tasks_concurrent`)

A worker pool (size = `pacer.concurrency`, capped by `max_concurrency`) parallelizes request
**latency** — the real bottleneck against a remote target — while the pacer, serialized under a
lock, keeps the **global rate** inside the learned safe envelope. Workers share the EV-ordered
queue, the budget, the defence profile and the retry/park logic; the pool terminates cleanly when
the queue drains and nothing is in flight.

- When the target is **rate-bound** (tight limit), concurrency beyond rate × latency gives nothing
  — the pacer ceiling dominates (correct: don't trip the limiter).
- When the target is **latency-bound** (tolerant rate, slow responses), concurrency is a big win:
  ~5.6× over sequential with 6 workers at 20 ms/request in the benchmark.

Either way it never exceeds the safe rate, backs off on 429/5xx, and parks WAF walls.

## The wired confirmer (`confirm.py`)

```
EV-ranked READ leads (read_bola / chained / tenant)
  → build_probe_tasks: one safe GET replay per lead — the ATTACKER principal re-issues the
                       holder's own request (your own accounts; GET only)
  → run_tasks_concurrent: defence-aware, paced, parallel, budgeted, scope-guarded
  → DISPOSE by VALUE PRESENCE: a finding iff the attacker's response reproduces the holder's
                       object-specific private value on a CLEAN 2xx (never on a 403/429/WAF)
  → ConfirmFinding + replayable certificate
```

Precision on a hardened target: a **clean 403** is a correct non-finding (the boundary holds); a
**WAF/challenge** is parked and never confirmed; only a genuine cross-account value reproduction
counts. Writes/fields/state are **not** replayed here — confirming those safely is the reversible
intervention saga (Wall-7); confirm issues reads only.

## One command

```
iolite hunt --dir ./captures --roe engagement.json \
            --replay --principals-file accounts.json --base-url https://api.target.com
```

`accounts.json` = `{"alice": {"authorization": "Bearer …"}, "bob": {"authorization": "Bearer …"}}`
— your own accounts. It runs only behind an attested engagement, scope-guarded, read-only, with
the adaptive pacer; the dossier gains a "Live-confirmed (replay)" section and the learned defence
profile.

## Safety / legality (load-bearing)
Own accounts only; attested RoE required; scope enforced per request; the sender is read-only
(no writes); the pacer honors Retry-After and backs off (gentle AND fast). WAF walls are
recognised and parked, never attacked. IOLITE confirms exposure you can already reach with your
own accounts — it does not break authentication, solve challenges, or defeat WAFs.

## Honest floor
Replay confirms READ-side exposure. Parallelism helps only up to the target's safe rate (the pacer
is the global ceiling). The write/field/state families remain for the gated intervention. A
force-multiplier for an authorized hunter on the strongest targets — not an autonomous scanner.
