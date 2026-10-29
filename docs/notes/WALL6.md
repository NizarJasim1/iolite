# WALL-6 — learn the target, prove it offline, and reach the giants (v1.16)

> A hostile self-review of Wall-5 (v1.15), and the fixes. Wall-5 lifted intent to a
> relational lattice — real progress — but three things made it weaker than it sounded.
> Wall-6 names them and fixes them with wired, tested code.

## The critique of v1.15 (be your own harshest reviewer)

1. **Offline it confirmed nothing.** Every real candidate became a "lead". The hard part
   — confirmation, where false positives die — was entirely punted to a live step. The
   tool didn't close a single bug by itself.
2. **The "Zanzibar lattice" was a wordlist.** Field/state semantics came from hardcoded
   English (`role`, `status`, `owner_id`). That is itself a known-shape heuristic — exactly
   what the mission says to transcend — and blind to a target whose fields are `estado`,
   `propietario`, `nivel`.
3. **Chained was near-fake** ("the attacker already saw the id" — contradictory), and
4. **nothing practical for the biggest GraphQL targets**, where the money and competition
   actually are.

## The four fixes, and how they interlock

### 1. See the response — `capture.py`
Wall-5 reasoned over endpoints + holdings only; it never looked at what the server
RETURNED. The `CapturedExchange` is one request **and its response** by one of the
operator's own principals. Everything below is built on it. Honest degradation: a thin
model with no responses corroborates nothing (leads only) — never a fabricated finding.

### 2. Learn the schema, don't match words — `schema_learn.py`
No field is classified by its name. Semantics come from behaviour:

| learned class | behavioural signal | bug it unlocks |
|---|---|---|
| server-authoritative | appears in RESPONSES, never SENT | BOPLA by definition |
| ownership / identity | per-principal value sets disjoint & stable | owner scoping |
| state | low-cardinality, CHANGES over an object's life | workflow-context |
| **terminal state** | **absorbing node of the observed transition graph** | state-exclusion |

The terminal-state learner is the key idea: a value is terminal when objects transition
INTO it and no mutation is ever observed after — so `archivado`, `已归档`, or any token is
learned as "closed" with zero English knowledge. The wordlist remains only as a weak prior.

### 3. Prove it offline, zero requests — `corroborate.py`
The practical win. A hunter who captured two of their own accounts usually already HOLDS
the proof:

- **read-BOLA** — B's capture contains A's owned object carrying A's discriminating
  private value (object-specific, not a shared default) ⇒ proven cross-user read.
- **tenant** — a foreign-tenant principal received a tenant-scoped object ⇒ proven.
- **BOPLA** — a write SENT a server-authoritative field and the server REFLECTED it ⇒
  proven property escalation.

Sound (reads only captures the operator legitimately holds), zero-harm (no traffic),
shared-default-gated (a value common across many objects never corroborates). This is the
first time IOLITE confirms a bug without a live step.

### 4. Reach the giants — `graphql_probe.py`
Where the fiercest, highest-paying programs live:

- **global-id enumeration** — decode `base64("Order:1007")` / `gid://app/Order/1007`,
  increment/decrement, re-encode ⇒ neighbour ids to test cross-principal.
- **alias-batch packing** — one document, N aliased fields, N different ids ⇒ test dozens
  of objects in ONE request, defeating per-request rate limits and object throttling.
- **nested-object authorization** — find `order → customer → paymentMethods` traversals
  to a sensitive type from the type graph: the edge servers authorize the root but forget.

## How it runs (the upgraded kill-chain)

```
CAPTURE   request+response exchanges (own principals)
  → LEARN    schema from behaviour (language-agnostic)
  → CORROBORATE  prove bugs OFFLINE from the captures (0 requests)   <-- new, real confirmations
  → GENERATE wide divergence over the LEARNED lattice
  → REDUCE / SCHEDULE
  → CONFIRM  the one metamorphic gate (offline = honest leads + refuse unsafe; live = ONYX)
  → REPORT   corroborated findings + EV-ranked leads + learned schema
```

## Safety / legality (unchanged, load-bearing)
Corroboration sends nothing. Generation proposes; the single gate disposes. Scope-guard,
non-destructive defaults, rate governor, human-gating and preflight fail-closed still bound
every live step. Own principals only. Authorized-testing RoE throughout.

## Honest floor
Offline corroboration needs response-bearing, multi-account captures; without responses
everything is a live lead. Recall is bounded by evidence, generators and budget. The field
T1 run remains. The transfer gap is narrowed again — the tool now learns the target's own
vocabulary and proves what the captures already contain — never eliminated.

## References
- Zanzibar (USENIX ATC 2019); OWASP API Top 10 2023 (BOLA/BOPLA/BFLA); empirical BOLA
  taxonomy (100+ disclosures); metamorphic security testing; GraphQL global-id / alias-batch
  authorization testing (Shopify/GitLab/HackerOne-class patterns).
