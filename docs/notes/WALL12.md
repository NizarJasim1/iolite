# WALL-12 — see it live, and make the write path one step

> Two ergonomics capstones: a browser dashboard that shows the authorization model building as you
> browse, and an auto-generated intervention config so the write path is one reviewed step.

## The live dashboard (`iolite watch`)

`iolite watch --scope api.target.com` now prints a dashboard URL (http://127.0.0.1:PORT/). Open it
and browse the target with your accounts; the page updates ~1 s and shows:

- **Live feed** — confirmations (red), learned boundaries (green), enforcement denials / defences
  (amber), enumeration leaks (orange), each the instant it happens.
- **Learned policy** — per object type: intent · enforced? · confidence · owner-allow / non-owner-deny
  / violations (the contrast-learned model from Wall-9).
- **Relation graph** — each principal with its JWT role / tenant / sub and how many objects it owns,
  plus the confirmed cross-account exposures as edges.
- **Defence profile** — WAF vendor, learned safe rate, block counts (Wall-10).
- **EV-ranked leads** — the scanner-blind families with the exact probe and the intent-deny
  derivation.

It is served by the collector over loopback only, reads solely your own session, and adds no
network destination beyond your local collector. Routes: `/` (page), `/events?since=N` (incremental),
`/policy`, `/graph`, `/snapshot` (cached), `/dossier`.

## Auto intervention config (`iolite gen-target`)

```
iolite gen-target --dir ./captures --scope api.target.com \
                  --principals-file accounts.json --out target.json
```

It derives, from your captures, the engine's `target.json`:
- `host` / `base_url`,
- static `auth` from your own accounts (`accounts.json` = `{pid: {header: value}}`),
- one **kind** per object type that has an observed create + read: `create` (the POST, with a
  title-ish field → `{{title}}` and a secret-ish field → `{{secret}}` so the engine can plant and
  detect a unique private value) and `read` (`GET /type/{{id}}`).

Every uncertain field carries a `_TODO`, and a read-only type (no create observed) is surfaced
rather than dropped. Then:

```
python3 -m iolite.intent target.json      # the gated engine: ScopeGuard + own-principals, writes dry-run until attested
```

This removes the last piece of hand-work on the write/intervention path.

## Safety / legality (load-bearing)
`gen-target` writes a PROPOSAL; IOLITE never auto-runs it, and the engine keeps writes dry-run until
you attest. The dashboard is loopback-only and shows only your own session. Everything live is own-
accounts-only, in scope, behind an attested engagement. Review the generated config before any
write-capable run — an auto-derived create/read pair can be wrong, and a wrong write is on you.

## Honest floor
The generator is best-effort pattern derivation, not a guarantee the create/read pair is correct —
hence the review gate. The dashboard reflects what you exercised; it does not browse for you. A
force-multiplier for an authorized hunter, start to finish — not an autonomous scanner.
