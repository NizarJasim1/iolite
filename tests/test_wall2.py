"""Wall-2 regression (in-process, deterministic). Runs all three Wall-2 kernels'
own assertions. Run from the IOLITE project root:  python3 tests/test_wall2.py
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "iolite", "intent"))
import wall2_scale, wall2_deep, wall2_zerofp   # noqa: E402

def main() -> int:
    wall2_scale.main()     # 480k→36; class+cohort bugs under budget
    print("-" * 40)
    wall2_deep.main()      # learned partition + EV bandit > uniform
    print("-" * 40)
    wall2_zerofp.main()    # FP=0 measured; detection widened 1→4
    print("WALL-2 REGRESSION PASS (quotient + learned/bandit + zero-FP/widening)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
