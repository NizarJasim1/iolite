"""Golden snapshot — the demo spec is byte-stable (version normalised).
Regenerate intentionally with `python tests/_gen_golden.py` after an accepted change."""
import json
import os

from tests.golden_util import demo_spec_normalized, GOLDEN_PATH


def test_demo_spec_matches_golden():
    assert os.path.exists(GOLDEN_PATH), "golden missing — run tests/_gen_golden.py"
    with open(GOLDEN_PATH, encoding="utf-8") as fh:
        golden = json.load(fh)
    current = demo_spec_normalized()
    a = json.dumps(current, sort_keys=True, indent=2)
    b = json.dumps(golden, sort_keys=True, indent=2)
    assert a == b, "demo spec drifted from golden (regenerate if intentional)"
