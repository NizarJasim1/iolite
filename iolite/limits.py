"""
Resource caps — defense-in-depth against hostile / huge / pathological inputs.

IOLITE reads attacker-influenced material (a target's own JS, HAR captures, JSON
docs). A miner with no bounds is a denial-of-service waiting to happen. Every cap
here is a fixed, auditable integer (QL4); exceeding one degrades gracefully
(truncate / stop / skip with a note) — never a hang or a crash.
"""

from __future__ import annotations

# per-file read caps
MAX_INPUT_BYTES = 8 * 1024 * 1024      # any text file: read at most 8 MiB
MAX_JSON_BYTES = 8 * 1024 * 1024       # JSON doc size before parse
MAX_JSON_DEPTH = 200                    # nesting depth before parse (C json parses 5000-deep without erroring)

# JS miner caps
MAX_JS_BYTES = 6 * 1024 * 1024         # scan at most 6 MiB of a bundle
MAX_QUOTED_MATCHES = 200_000           # quoted-path scan positions
MAX_CONCAT_PARTS = 64                  # parts in a single concatenation chain
MAX_ENDPOINTS = 20_000                 # distinct endpoints per source

# sourcemap caps
MAX_SOURCES = 5_000                    # source files mined from one map
MAX_SOURCE_BYTES = 1024 * 1024         # per-source code size

# HAR caps
MAX_HAR_ENTRIES = 100_000              # entries processed from one HAR
MAX_BODY_BYTES = 512 * 1024            # request body parsed as JSON
