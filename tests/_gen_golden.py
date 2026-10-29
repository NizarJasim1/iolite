#!/usr/bin/env python3
"""Regenerate the golden demo spec. Run intentionally after an accepted output change:
   python tests/_gen_golden.py
The version field is normalised to <VERSION> so version bumps don't churn the golden."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tests.golden_util import demo_spec_normalized, GOLDEN_PATH  # noqa

spec = demo_spec_normalized()
with open(GOLDEN_PATH, "w", encoding="utf-8") as fh:
    json.dump(spec, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"wrote golden → {GOLDEN_PATH}")
