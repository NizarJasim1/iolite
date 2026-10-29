"""
The ONYX bridge — a REAL link, not a printed command.

  * locate()        find ONYX/AuthPath (env ONYX_PATH / IOLITE_ONYX_PATH, or importable)
  * verify_spec()   run a IOLITE spec through ONYX's OWN loaders, offline, and report
                    exactly what ONYX will see (principals, contract, recognised probes,
                    any mismatch) — the operational proof the two tools agree
  * launch_server() start ONYX's control center as a subprocess and return its URL
                    (so IOLITE's HUD can open ONYX's HUD — the two interfaces linked)
  * scan()          shell out to `authpath scan spec.json` against a live target

verify_spec is offline and always safe; launch/scan touch subprocesses/network and
are opt-in. Nothing here modifies ONYX — IOLITE only drives it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request

ONYX_HUD_PORT = 8787


def wait_until_up(url: str, timeout: float = 8.0) -> bool:
    """Poll a URL until it answers (server finished booting), or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.5) as r:
                if r.status < 500:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def locate() -> str | None:
    """Return the ONYX repo root (and put it on sys.path), or None."""
    for env in ("IOLITE_ONYX_PATH", "ONYX_PATH"):
        p = os.environ.get(env)
        if p and os.path.isdir(p):
            if p not in sys.path:
                sys.path.insert(0, p)
            return p
    try:
        import authpath  # already importable / installed
        return os.path.dirname(os.path.dirname(os.path.abspath(authpath.__file__)))
    except Exception:
        return None


def available() -> bool:
    if locate() is None:
        return False
    try:
        import authpath  # noqa
        return True
    except Exception:
        return False


def verify_spec(spec: dict) -> dict:
    """Run `spec` through ONYX's real loaders and report what ONYX would see.
    Offline and non-destructive. This is the operational agreement check."""
    if not available():
        return {"available": False,
                "hint": "set ONYX_PATH to the ONYX repo, or `pip install -e` it"}
    try:
        from authpath.cli import _principals, _req
        from authpath.scope_guard import ScopeConfig
    except Exception as e:
        return {"available": False, "error": f"import failed: {type(e).__name__}: {e}"}

    try:
        host = spec.get("base_url", "").split("://", 1)[-1].split("/", 1)[0]
        principals = _principals(spec)
        ScopeConfig(**{**{"allowed_hosts": [host]}, **spec.get("scope", {})})
        contract_keys = set(spec.get("contract", {}))
        items = list(spec.get("seed", [])) + list(spec.get("probe", []))
        recognised, unknown = 0, []
        for it in items:
            key = _req(it, host).endpoint_key()
            if key in contract_keys:
                recognised += 1
            else:
                unknown.append(key)
        return {
            "available": True, "parses": True,
            "principals": sorted(principals.keys()),
            "contract_endpoints": len(contract_keys),
            "requests": len(items),
            "recognised": recognised,
            "unrecognised": sorted(set(unknown)),
            "agree": recognised == len(items),
        }
    except Exception as e:
        return {"available": True, "parses": False,
                "error": f"{type(e).__name__}: {e}"}


def launch_server(port: int = ONYX_HUD_PORT):
    """Start ONYX's control center as a subprocess. Returns (proc, url) or (None, msg).

    Idempotent: if something is ALREADY serving on the port (e.g. an ONYX started
    by a previous tab-open, or the user ran it by hand), reuse it instead of
    spawning a duplicate that would die with 'address already in use'."""
    root = locate()
    if root is None:
        return None, "ONYX not found (set ONYX_PATH)"
    url = f"http://127.0.0.1:{port}"
    if wait_until_up(url, timeout=0.8):          # already up → reuse, don't double-spawn
        return "existing", url
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "authpath", "serve", "--no-open", "--port", str(port)],
            cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc, url
    except Exception as e:
        return None, f"could not launch ONYX: {type(e).__name__}: {e}"


def scan(spec_path: str, out_dir: str = "reports", insecure: bool = False,
         timeout: int = 900) -> dict:
    """Shell out to `authpath scan` against a LIVE authorised target. Requires the
    spec to carry real (un-redacted) tokens and a reachable base_url."""
    root = locate()
    if root is None:
        return {"ok": False, "error": "ONYX not found (set ONYX_PATH)"}
    try:
        spec = json.load(open(spec_path))
        if any(str(v).startswith("$TOKEN_") for p in spec.get("principals", [])
               for v in p.get("auth", {}).values()):
            return {"ok": False, "error": "spec tokens are redacted — restore real "
                    "credentials before a live scan"}
    except Exception:
        pass
    cmd = [sys.executable, "-m", "authpath", "scan", os.path.abspath(spec_path),
           "--out", out_dir]
    if insecure:
        cmd.append("--insecure")
    try:
        r = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0, "stdout": r.stdout[-8000:], "stderr": r.stderr[-2000:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "scan timed out"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
