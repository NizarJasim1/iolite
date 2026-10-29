# Development notes

The build plan and the hardening rounds IOLITE went through. Each `WALL*.md` describes
one hard problem (a capability gap or a failure mode found by testing), how it was
solved, and the evidence run behind it. Evidence scripts in `wall*_evidence/` were run
against local, intentionally vulnerable targets such as VAmPI and crAPI.

Numbers in these notes are self-measured on those targets unless stated otherwise.
