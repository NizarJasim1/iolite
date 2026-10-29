#!/usr/bin/env python3
"""
Tiny stdlib test runner (no pytest needed).

Discovers every `test_*.py` in this directory, runs every `test_*` function, and
reports pass/fail. Run from the repo root:  python tests/run_all.py
"""
import importlib.util
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _load(path):
    name = "qtest_" + os.path.basename(path)[:-3]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    files = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    passed = failed = 0
    failures = []
    for f in files:
        mod = _load(os.path.join(HERE, f))
        for attr in sorted(dir(mod)):
            if not attr.startswith("test_"):
                continue
            fn = getattr(mod, attr)
            if not callable(fn):
                continue
            try:
                fn()
                passed += 1
            except Exception as e:  # noqa: BLE001
                failed += 1
                failures.append((f, attr, e, traceback.format_exc()))
                print(f"FAIL {f}::{attr}: {type(e).__name__}: {e}")
    print(f"\n{passed} passed, {failed} failed")
    if failures:
        print("\n--- tracebacks ---")
        for f, attr, _e, tb in failures:
            print(f"\n{f}::{attr}\n{tb}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
