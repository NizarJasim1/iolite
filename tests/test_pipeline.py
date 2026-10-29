"""Unified kill-chain regression: one pipeline runs all four walls as stages and
must catch 6 bug classes at FP=0, refuse the irreversible write, keep writes
net-zero, and reduce the raw space by the quotient. Run from the repo root:
    python3 tests/test_pipeline.py
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "iolite", "intent"))
import pipeline   # noqa: E402

def main() -> int:
    pipeline.main()          # asserts: 6 classes, FP=0, 1 refused, writes net-zero, quotient reduces
    print("UNIFIED PIPELINE REGRESSION PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
