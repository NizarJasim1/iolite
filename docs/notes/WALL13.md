# WALL-13 — the Operations Table (dashboard redesign)

> The dashboard is now a tactile instrument: the authorization model is a living force-graph you
> can grab, fling and interrogate, over a blueprint HUD, with physical, spring-driven controls.
> One self-contained file, pure vanilla JS/CSS/canvas, served by the collector; alive on open via
> a built-in demo stream and driven by real session data under `iolite watch`.

## Design language
- **Subject → form.** IOLITE is a navigation gem; the dashboard is an *operations table* — a
  blueprint/HUD surface of fine white gridlines with pointer parallax, faceted (corner-cut)
  panels with a violet→cyan hairline top edge. Boldness is spent in ONE place: the physics graph.
- **Colour carries meaning, not decoration.** pleochroic violet/indigo/cyan for identity;
  confirmations = red, enforced boundaries = green, defences = amber, enumeration = orange.
- **Type.** A display sans for headings, a mono for data/instruments; tabular numerals everywhere
  numbers change.

## The physics (every moving thing is physical)
- **Force-graph** (canvas, 60fps): Coulomb repulsion + Hooke spring edges (ownership short, taut;
  confirmation long, glowing) + centre gravity + velocity damping. Nodes are **draggable and
  flingable** (velocity carried on release), **click to pin**, **double-click to release**,
  **hover for a tooltip**. A confirmation fires a **shockwave** (impulse to every free node).
- **Panels**: drag by the header with inertia and a velocity-tilt; a soft spring returns them
  inside the viewport; RESET LAYOUT springs them home; collapse animates.
- **Buttons**: press scales down with a pointer-origin ripple; chips slide/scale.
- **Instruments**: the safe-rate gauge arc eases to its value; the latency sparkline streams; top
  counters count up; feed rows spring in from the top; confirmations raise a floating toast.

## Live vs demo
On load the page probes the collector (`/status`). Reachable → **LIVE** (real session). Not
reachable (opened standalone) → **DEMO STREAM**: an in-page simulator emits a believable live
feed (owners create objects, non-owners get denied → boundaries learned, cross-account reads →
confirmations, plus rate-limit/WAF/challenge/auth-expiry defences) so the whole table is animated
immediately. A badge shows which mode is active.

## Data surface (unchanged engine, new views)
`LiveSession` gained a bounded `event_log` and a `graph()` (principals with JWT role/tenant/sub +
ownership, typed objects, confirmation edges). The collector serves `/` (this page), `/events?since=`
(incremental), `/policy`, `/graph`, `/snapshot` (cached leads), `/dossier`.

## Accessibility & robustness
`prefers-reduced-motion` disables physics/animation and snaps to final states; controls are
keyboard-reachable; layout is responsive to phone width; JS is dependency-free and validated. The
page is loopback-only and shows only the operator's own session.
