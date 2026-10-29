# WALL-7 — field-ready: real captures in, proven bugs out

> The self-audit said the deep layer was demo-only: responses were discarded, nothing was
> reachable from the CLI, the live confirmer was external, and the quotient truncated.
> Wall-7 makes it a thing you actually run on an authorized target.

## The one command

```
iolite hunt --dir ./captures --scope api.target.com --authorized-by https://hackerone.com/<program>
```

`./captures` holds one HAR per account you control (`alice.har`, `bob.har`, …), exported
from your browser or Burp while using the target normally with each account. Output: a
dossier at `./captures/iolite_dossier.md`.

Add `--live --roe engagement.json --target target.json` to also run the gated interventional
confirmer (see Safety).

## The pipeline (what `hunt` does)

```
per-account HARs
  → har_capture: exchanges WITH responses (fields + ids the server returned, owned flag),
                 out-of-scope hosts dropped
  → schema_learn: learn server-authoritative / ownership / state / terminal fields (any language)
  → corroborate: PROVE bugs OFFLINE from the captures — 0 requests               ← ready to submit
  → model_from_exchanges + relation_model: real surface model + authorization lattice
  → divergence: EV-ranked leads across the scanner-blind families, each with a derivation
  → (optional) engine.run_target: interventional live confirm behind preflight
  → dossier: a submittable Markdown report
```

## Why this is the fix, point by point

| audit finding | Wall-7 fix |
|---|---|
| `har_ingest` discarded response bodies → corroborate dead on real data | `har_capture` parses responses (JSON + base64) into evidence |
| deep layer unreachable from the CLI | `iolite hunt` wires it to a real captures folder |
| live confirmer external / a stub | reuse the tested `engine.run_target` (local-app proof in `test_intent_offline.py`), gated |
| quotient truncated silently | every instance preserved as a ranked lead (degrade by value) |

## The two ways it confirms

1. **Offline corroboration (zero traffic, ready now).** If one account's capture already
   contains another account's private object (same discriminating value), that is a proven
   BOLA — no packet is sent. Also cross-tenant delivery and reflected server-authoritative
   fields (BOPLA). This is the safest, fastest win and needs nothing but your captures.

2. **Live intervention (gated).** `engine.run_target` creates objects as your own accounts,
   then checks whether a second account can reproduce the first's discriminating private
   value — a finding proven by value presence, never a status code. It runs ONLY when:
   - an `Engagement` (roe.py) is **attested** with a real authorization basis, and
   - `automation_permitted` is true, and
   - `preflight` passes (fail-closed), under ScopeGuard + a rate Governor,
   - own accounts only, reads-only unless you explicitly allow reversible writes.

## How to capture (practical)

- Log in as account A in your browser; use the app normally (open your objects, lists,
  settings). Save as `captures/a_alice.har` (DevTools → Network → Save all as HAR).
- Repeat as account B → `captures/b_bob.har`. For the strongest offline win, in B's session
  also open an object id that belongs to A (if the app lets you) — that is exactly the
  evidence corroboration proves.
- For GraphQL targets, `graphql_probe` turns a captured global id into neighbour ids and a
  single alias-batch query so you test many objects in one request (rate-limit friendly).

## Safety / legality (load-bearing, unchanged)

Offline sends nothing. The live path is scope-guarded on every request, rate-governed,
own-accounts-only, reads-only by default, human-initiated, and fail-closed without an
attested RoE. Out-of-scope hosts are dropped at ingestion. IOLITE cannot verify your
authorization for you — only you can, by attesting in the engagement. Use only on programs
whose scope explicitly permits this testing. Start on OWASP VAmPI / crAPI before any real
program.

## Honest floor

Offline corroboration needs response-bearing, multi-account captures. The live auto-
intervention needs a small `target.json` describing login + one create/read pair per object
type (template in the engine docs). Recall is still bounded by what you captured, which
generators exist, and your budget. IOLITE is a force-multiplier for an authorized hunter,
not an autonomous scanner.
