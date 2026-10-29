# WALL-14 — the living identity (interactivity without a redesign)

> The dashboard keeps its established identity exactly — same palette, the `◈ IOLITE LIVE`
> pleochroic header, the faceted three-column card grid — and becomes interactive *in place*.
> The authorization model is now a force-graph you can grab and fling, living inside the existing
> "Principals & ownership" card; the other cards gained count-ups, filter chips, spring-in rows and
> a confirmation toast. One self-contained file, pure vanilla JS/CSS/canvas, served by the collector.

## Why this exists
v1.23 redesigned the surface into a new "operations table." That changed the visual identity, which
was not wanted: the identity was already approved at v1.22. v1.14→v1.23 engine work stands; this
wall is purely the surface returning to the approved look while keeping the one genuinely useful
idea from v1.23 — a physical, interrogable view of the ownership model — folded back *into* that
look rather than replacing it.

## What is fixed in stone
The v1.22 identity is reproduced exactly: the `:root` tokens (`--bg:#0b0b14`, `--panel:#14141f`,
the violet/indigo/cyan `--v/--i/--c` family, …), the header mark, the `.wrap` 3-column grid, the
`.card` corner-cut clip-path with its violet→cyan hairline top edge, and the `.foot`. No colour or
layout-language change. New colour is drawn only from that same palette (graph principals violet,
admin pink-violet, objects cyan/indigo/violet/green/amber, confirmations red) so the graph reads as
part of the card, not a foreign element.

## What came alive (all additive, in-identity)
- **Force-graph in the ownership card** (canvas, IIFE `G`): Coulomb repulsion + Hooke ownership
  springs + centre gravity + damping. Nodes are **draggable and flingable** (velocity carried on
  release), **click to pin**, **hover for a tooltip** (`Tip`). Confirmed cross-account exposures are
  glowing red filaments. `G.focus(objectId)` flings the camera/selection to an object; `G.shock()`
  sends an impulse through the graph on a new confirmation.
- **Header count-ups** (`count()`): tabular-number roll-ups for principals / objects / boundaries /
  confirmations.
- **Feed** — filter **chips** (`chips()`) narrow by event kind; new rows **spring in** (`row()`);
  a confirmation raises a **toast** (`toast()`), **flashes** the pill (`flash()`) and calls
  `G.shock()`.
- **Policy table** — ratio bars show allow/deny per object type; a row is clickable → `G.focus`.
- **Leads** — clickable → `G.focus`; each has a copy-the-probe control.
- **LIVE/DEMO badge** (`badge()`): reflects whether a real collector answered `/status`.

## Alive on open (the v1.22 bug this closes)
Opened standalone, v1.22 sat empty until a collector fed it. A built-in demo simulator (`SIM`) now
emits a believable live stream — owners create objects, non-owners are denied (→ boundaries
learned), cross-account reads land as confirmations, interleaved with rate-limit / WAF / challenge /
auth-expiry defence events — whenever `/status` is unreachable. Under `iolite watch` the real
`LiveSession` data takes over; the badge shows which is active. Poll loops: `tick()` (1100 ms,
`/events` + `/status`) and `slow()` (3500 ms, `/policy` + `/graph` + `/snapshot`).

## Data surface (unchanged)
The collector still serves `/` (this page), `/events?since=` (incremental), `/policy`, `/graph`,
`/snapshot`, `/dossier`. The page consumes exactly those shapes; no engine or endpoint changed.

## Accessibility & robustness
`prefers-reduced-motion` disables physics/animation and snaps to final states; controls are
keyboard-reachable; the grid is responsive to phone width; JS is dependency-free, `node --check`
clean, and the full load path runs under a DOM/canvas stub with no runtime error. The page is
loopback-only and shows only the operator's own session.
