"""Wall-3 LIVE test against VAmPI (independent target). Skips cleanly if VAmPI is
not running on :5000. Additive; not wired into run_all.py.
Run:  bash iolite/intent/targets/get_vampi.sh &   # then, from repo root:
      python3 tests/test_wall3_saga_vampi.py
"""
import os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(os.path.dirname(HERE), "iolite", "intent")
sys.path.insert(0, PKG)

def vampi_up() -> bool:
    try:
        urllib.request.urlopen("http://127.0.0.1:5000/createdb", timeout=3)
        return True
    except Exception:
        return False

def main() -> int:
    if not vampi_up():
        print("SKIP: VAmPI not running on :5000 (start it with iolite/intent/targets/get_vampi.sh)")
        return 0
    os.environ.setdefault("WALL3_WAL", "/tmp/wall3_test_wal.json")
    import wall3_saga   # runs its main() on import? no — guarded. call main().
    rc = wall3_saga.main()
    # wall3_saga.main() asserts FINDING + net-zero + recovery internally and returns None/0
    print("WALL-3 LIVE TEST: passed (see run output above)")
    return rc or 0

if __name__ == "__main__":
    sys.exit(main())
