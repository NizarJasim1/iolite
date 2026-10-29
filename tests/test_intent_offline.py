"""Wall-1 offline regression (additive; standalone, not wired into run_all.py).
Boots the bundled local vulnerable app and asserts the value-presence verdicts.
Run from the IOLITE project root:  python3 tests/test_intent_offline.py
"""
import json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))                 # iolite/tests
PKG = os.path.join(os.path.dirname(HERE), "iolite", "intent")     # iolite/iolite/intent
sys.path.insert(0, PKG)
import engine   # noqa: E402  (imported by path; no relative deps)

def main() -> int:
    srv = subprocess.Popen([sys.executable, os.path.join(PKG, "targets", "local_vuln.py")])
    try:
        time.sleep(1.3)
        with open(os.path.join(PKG, "targets", "local.json")) as fh:
            cfg = json.load(fh)
        res = {f.kind: f.verdict for f in engine.run_target(cfg)}
        print("verdicts:", res)
        assert res.get("notes") == "FINDING", res
        assert res.get("cards") == "CLEAN", res
        print("INTENT OFFLINE REGRESSION PASS (notes=FINDING, cards=CLEAN)")
        return 0
    finally:
        srv.terminate()

if __name__ == "__main__":
    sys.exit(main())
