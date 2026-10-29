# WALL-8 — scan while you browse (live, passive, instant)

> The answer to "make it scan during use": don't capture-then-analyse. Observe your own
> browsing with each account, build the authorization-intent model incrementally, and
> confirm cross-account exposure the instant it appears — without the tool sending anything.

## One command

```
iolite watch --scope api.target.com
```

It starts a loopback collector and prints a one-line snippet per account. Paste account A's
snippet in A's browser console, account B's in B's. Browse normally. The moment B's session
receives an object A owns (with A's private value), the terminal prints:

```
[HIGH] BOLA confirmed live: B read A's 500 — account B reproduced A's private value(s) ['4111-…-7777'] for 500
```

Ctrl-C writes a submittable dossier.

## How it works

```
your browser (account A, account B)
  → iolite_live_hook.js  (wraps fetch/XHR, records request+response, POSTs to loopback)
  → collector.py  (127.0.0.1 only, scope-enforced)
  → live_session.py
        HOT PATH (per event, O(fields)) → instant cross-account confirmation
        snapshot() (on demand)          → full Wall-5/6: learn → corroborate → lattice → EV leads → dossier
```

### Faster
Every event updates two online indexes (`value → objects`, `object/principal → values`) and
checks a couple of conditions — O(fields), not a recompute. Alerts are instant; the heavy
divergence pass runs only when you ask for the dossier.

### More accurate
It sees the real **response bodies**, so the discriminating value (a token, a card number, a
UUID) is the actual proof — not an inference. And the learned schema sharpens as more objects
arrive: a value that shows up across many objects is demoted from "secret" to "shared
default", so false discriminators fall away the longer you browse.

### The methodology, continuously
`snapshot()` runs the exact Wall-5/6 pipeline (relational authorization lattice + divergence
+ metamorphic oracle) over the growing live corpus, so the intent model you built is applied
to live data, not a frozen capture.

## What it confirms live, with zero crafted requests
- **read-BOLA** — a non-owner session reproduced an owner's object-specific private value.
- **cross-tenant** — a session in tenant T2 received an object owned in tenant T1.
(Write/field/state/chained families still surface as EV-ranked leads in the snapshot dossier;
confirming those safely is the gated intervention path, Wall-7.)

## Capturing well (practical)
- Use two real browser profiles / containers, one per account, both in scope.
- As A: open your objects, lists, settings, an order, a document. As B: do the same, and —
  if the app lets you — try opening an id that belongs to A. That single action is exactly
  what the hot path proves.
- For GraphQL, `graphql_probe` turns one captured global id into neighbour ids and a single
  alias-batch query so you exercise many objects in one legitimate request.

## Safety / legality (load-bearing)
Passive: the tool crafts no request; the hook only observes traffic your own client already
makes, as your own accounts, in your own session, in scope. The collector binds to 127.0.0.1
only and enforces scope (out-of-scope hosts are dropped). Nothing leaves your machine except
the calls your browser was already making. Load the hook only in accounts and scopes that are
yours and that the program permits. Start on OWASP VAmPI / crAPI.

## Honest floor
It confirms what your browsing actually exposes; it does not crawl or log in for you. Recall
is bounded by what you open with each account. The write/field/state families still need the
gated live intervention (Wall-7) to confirm. IOLITE is a force-multiplier for an authorized
hunter, not an autonomous scanner.
