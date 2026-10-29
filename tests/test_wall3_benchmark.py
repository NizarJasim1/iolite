"""Wall-3 FAIR benchmark regression: boot the labeled benchmark app, run the
generalized HTTP write-BOLA engine, assert precision=1.0, recall(findable)=1.0,
zero harm, zero litter. Deterministic verdicts; offline. Run from repo root:
    python3 tests/test_wall3_benchmark.py
"""
import os, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(os.path.dirname(HERE), "iolite", "intent")
sys.path.insert(0, PKG)

def main() -> int:
    srv = subprocess.Popen([sys.executable, os.path.join(PKG, "wall3_benchmark_app.py")])
    try:
        for _ in range(20):
            try:
                urllib.request.urlopen("http://127.0.0.1:8911/labels", timeout=1); break
            except Exception:
                time.sleep(0.3)
        import wall3_bench_runner
        wall3_bench_runner.run()            # asserts precision/recall/safety internally
        print("WALL-3 BENCHMARK REGRESSION PASS")
        return 0
    finally:
        srv.terminate()

if __name__ == "__main__":
    sys.exit(main())
