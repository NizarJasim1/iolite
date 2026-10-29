# WALL-9 — deep response reading + a contrast-learned intent model

> The self-critique of Wall-8: the live reader was shallow and the intent builder ignored the
> most reliable authz signal — the contrast between ALLOW and DENY across accounts. Wall-9
> reads the whole response and learns the policy from that contrast, precisely.

## What a single call now yields (`observation.py`)

For every request/response your browser makes, IOLITE extracts one `Observation`:

| dimension | extracted | why it matters |
|---|---|---|
| enforcement | ALLOW / AUTHZ-DENY (403) / AUTHN-DENY (401) / MASKED (404) / RATE (429) | a denial *teaches* the boundary |
| identity | `sub` / `role` / `tenant` from the JWT **claims** (not the token) | ownership can be read, not guessed |
| relationships | server-stated `owner_id` / `parent_id` / `tenant_id` / `state` | real Zanzibar tuples |
| structure | every nested object + every item of a **collection** | the ids a principal can enumerate |
| fields | typed id / secret / enum / timestamp / content | precise discriminators |

Only JWT **claims** are decoded, in the browser, and sent — never the token itself.

## Learning the policy by contrast (`policy_learn.py`)

Instead of guessing intent from field names, the builder learns the access-control function
from what actually happened:

- **Ownership is read, not guessed** — `owner_id == your sub` ⇒ you own it; `owner_id ==
  another account's sub` ⇒ they do. Far fewer false links than "sole holder".
- **A boundary is LEARNED by contrast** — owner gets ALLOW+value AND a non-owner gets
  403/401/404 on the same type ⇒ an *enforced* owner-scoped boundary, confidence growing with
  each confirming observation. (v1.18 ignored denials entirely.)
- **A violation is the opposite contrast** — a non-owner reproduced the owner's private value
  ⇒ BOLA, pinned to the real owner.
- **Enumeration exposure** — a list/nested response returns ids owned by others ⇒ the account
  can harvest foreign ids (the chained-BOLA precursor).

The learned model is a table per object type: `intent · enforced? · confidence · owner-allow ·
non-owner-deny · violations`, plus each principal's role/tenant/sub. It appears in the dossier
(section 0) and in `iolite watch`'s summary on stop.

## Live signals (`iolite watch`)

As you browse with two accounts, the terminal prints, in real time:

```
[HIGH] BOLA confirmed live: bob read alice's 1001        (precise, via owner_id)
[ •  ] boundary evidence: carol denied (403) on alice's 1001
[ •  ] intent LEARNED: vault is owner-scoped AND enforced (owner allowed, non-owner denied) [medium]
[MED ] enumeration exposure: bob can list ids owned by others via GET /api/vault
```

## How to drive it well
- Browse as A (open your objects). Then as B: open your own objects **and** try opening an id
  that belongs to A. If B gets A's data → instant BOLA. If B gets 403 → the boundary is
  *learned enforced* (and every other type where you do this sharpens the model).
- The more you exercise both the allowed and denied paths, the stronger and more precise the
  intent model becomes.

## Safety / legality (unchanged, load-bearing)
Passive — the tool crafts nothing; the hook observes only your own accounts' own traffic, in
scope, in your session; it sends JWT claims (never tokens) to a loopback-only collector;
out-of-scope hosts are dropped. Own accounts only. Use only where the program's scope permits.

## Honest floor
The contrast learner needs the denial to actually occur — you must try another account's
object (and get the 403) for the boundary to be *learned enforced*; a boundary never contrasted
stays "owner_scoped / unenforced-unknown". Recall is bounded by what you exercise. The
write/field/state families still confirm via the gated intervention (Wall-7). A force-
multiplier for an authorized hunter, not an autonomous scanner.
