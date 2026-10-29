# Field-verification runbook — write-BOLA on crAPI (your machine)

The sandbox here has no Docker daemon, so the write-side engine is verified two
ways in-repo (see below). For a full field check against the canonical OWASP
target, run it on your own machine (Kali + podman/docker), where crAPI runs.

## In-repo verification (reproducible now, offline)
1. **Fair labeled benchmark** — real-distribution write-authz suite with decoys
   and safety/by-design misses. Measures precision/recall/safety:
   ```
   python3 tests/test_wall3_benchmark.py
   # -> PRECISION 1.000, RECALL(findable) 1.000, external effects 0, litter 0
   ```
2. **Independent live anchor** — a real write-side authz bug on code we did not
   write (VAmPI register mass-assignment), full saga + durable WAL:
   ```
   bash iolite/intent/targets/get_vampi.sh &   ;  sleep 8
   python3 tests/test_wall3_saga_vampi.py
   ```

## Field verification on crAPI (your Kali box)
1. Start crAPI (your existing compose) and provision **two accounts you own**
   (A and B) + capture their tokens.
2. Declare crAPI's mutating endpoints in an op-table like
   `iolite/intent/wall3_bench_runner.py::OPS` (method, path, body marker,
   change-detector, inverse). Put ONLY operator-vetted reversible ops on the
   allowlist; set `operator_asserts_no_external_effect` per op (crAPI sends
   mail via MailHog — treat anything that could email/charge as external →
   leave it OFF the allowlist so it is refused).
3. Point the engine's HTTP layer at `http://localhost:8888`, scope-guard that
   host, enable the durable WAL (`WALL3_WAL=/tmp/crapi_wal.json`), and run.
4. Expect: write/role/owner/soft-delete BOLA → FINDING (confirmed by owner
   read-back, then restored); hard-delete / mail-triggering ops → REFUSED;
   every created test object cleaned up; WAL empty at the end.

## Honesty
crAPI's documented BOLAs are mostly **reads** (vehicle location, mechanic
report) — already covered by Wall-1. Its write-side is thinner; confirm which
mutating endpoints lack ownership checks from your capture before declaring them.
The engine's value is the SAFE, net-zero confirmation + sweep, not a claim that
every target has a write-BOLA.
