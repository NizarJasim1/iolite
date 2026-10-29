"""Wall-4 soundness regression (in-process, deterministic). Runs the hardened
decision kernel's own assertions. Run from the IOLITE project root:
    python3 tests/test_wall4.py
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "iolite", "intent"))
import wall4   # noqa: E402

def main() -> int:
    wall4.main()            # asserts: universal-on-private FIRES; flaky/observer/public ABSTAIN; benign ABSTAIN
    print("WALL-4 REGRESSION PASS")
    return 0

if __name__ == "__main__":
    sys.exit(main())
