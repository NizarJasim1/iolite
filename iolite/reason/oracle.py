"""
reason · oracle — ONYX as the sound verdict source for the CEGAR loop.

The loop hypothesizes; the oracle DECIDES. Three implementations:

  * LiveOnyxOracle   — the real thing: shells out to `authpath scan` against a LIVE,
                       AUTHORISED, ATTESTED target, parses ONYX's findings, and maps
                       each confirmation back to the candidate that produced it.
                       Runs only on the operator's machine (real tokens, reachable
                       target). Confirmation is ONYX's, never reason's.
  * StaticOracle     — offline: no live target, so it returns UNKNOWN for every
                       candidate (verify-only). It NEVER fabricates a confirmation.
  * SimulatedOracle  — deterministic fake verdicts for tests / dry planning only.

A verdict is (confirmed True | False | None-unknown). False positives are ONYX's to
prevent; reason only routes the loop by the verdict it is given (QL5).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

from . import engine as _engine
from .. import onyx_link


@dataclass
class OracleVerdict:
    cand_key: str
    confirmed: bool | None            # True=Δstate breach, False=denied, None=unknown
    severity: str = ""
    note: str = ""
    leaked_ids: list[str] = field(default_factory=list)   # optional evidence for chaining


class Oracle:
    kind = "base"

    def test(self, model, cands, engagement) -> dict[str, OracleVerdict]:
        """Return {cand_key -> OracleVerdict} for the given candidate batch."""
        raise NotImplementedError

    @staticmethod
    def _unknown(cands) -> dict[str, OracleVerdict]:
        return {c.cand_key: OracleVerdict(c.cand_key, None, note="no live oracle")
                for c in cands}


class StaticOracle(Oracle):
    """Offline: parse-checks the spec through ONYX's loaders but cannot issue live
    requests, so every candidate stays UNKNOWN. Honest by construction — it never
    turns an unproven hypothesis into a confirmation."""
    kind = "static"

    def test(self, model, cands, engagement):
        spec = _engine.spec_from_candidates(model, cands, engagement)
        onyx_link.verify_spec(spec)   # parse/recognition sanity only; no verdicts
        return self._unknown(cands)


class LiveOnyxOracle(Oracle):
    """Drive ONYX against a live authorised target and read back real verdicts.

    Requires: an ATTESTED engagement, restored (un-redacted) tokens, a reachable
    base_url. Maps an ONYX finding to a candidate by endpoint (+object id when the
    finding exposes it); every other tested candidate in the batch is recorded as
    denied. Runs only where those preconditions hold (the operator's machine)."""
    kind = "live"

    def __init__(self, out_dir: str = "reason_reports", timeout: int = 900):
        self.out_dir = out_dir
        self.timeout = timeout

    def test(self, model, cands, engagement):
        if not engagement.attested():
            return self._unknown(cands)
        root = onyx_link.locate()
        if root is None:
            return self._unknown(cands)
        spec = _engine.spec_from_candidates(model, cands, engagement, redact=False)
        spec_path = os.path.join(self.out_dir, "cegar_batch_spec.json")
        os.makedirs(self.out_dir, exist_ok=True)
        with open(spec_path, "w", encoding="utf-8") as fh:
            json.dump(spec, fh, indent=2)
        export = os.path.join(self.out_dir, "cegar_batch_diag.json")
        cmd = [sys.executable, "-m", "authpath", "scan", os.path.abspath(spec_path),
               "--out", self.out_dir, "--export", os.path.abspath(export)]
        try:
            subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=self.timeout)
        except Exception as e:                       # noqa: BLE001
            return {c.cand_key: OracleVerdict(c.cand_key, None, note=f"scan error: {type(e).__name__}")
                    for c in cands}
        confirmed_eps = self._confirmed_endpoints(export, self.out_dir)
        out = {}
        for c in cands:
            hit = (c.method + " " + c.path) in confirmed_eps or c.endpoint_key in confirmed_eps
            out[c.cand_key] = OracleVerdict(
                c.cand_key, confirmed=bool(hit),
                severity=confirmed_eps.get(c.endpoint_key, {}).get("severity", "") if hit else "",
                note="ONYX Δstate" if hit else "denied by ONYX")
        return out

    @staticmethod
    def _confirmed_endpoints(export_path: str, out_dir: str) -> dict:
        """Best-effort, schema-robust parse of ONYX findings → {endpoint: {severity}}.
        Reads the diagnostics export if present, else the per-finding markdown dir."""
        eps: dict[str, dict] = {}
        try:
            data = json.load(open(export_path, encoding="utf-8"))
            for f in (data.get("findings") or []):
                ep = (f.get("endpoint") or f.get("classification", {}).get("endpoint")
                      or f.get("key") or "")
                if ep:
                    eps[ep] = {"severity": f.get("severity", "")}
        except Exception:
            pass
        if not eps and os.path.isdir(out_dir):
            for name in sorted(os.listdir(out_dir)):
                if name.endswith(".md"):
                    eps[name[:-3]] = {"severity": ""}
        return eps


class SimulatedOracle(Oracle):
    """Deterministic fake oracle for tests / offline demos. Confirms candidates whose
    endpoint_key is in `confirm_keys`; everything else denied. Never used for real
    findings — clearly labelled, never claims ONYX proof."""
    kind = "simulated"

    def __init__(self, confirm_keys=(), leaked=None):
        self.confirm_keys = set(confirm_keys)
        self.leaked = leaked or {}

    def test(self, model, cands, engagement):
        out = {}
        for c in cands:
            ok = c.endpoint_key in self.confirm_keys
            out[c.cand_key] = OracleVerdict(
                c.cand_key, confirmed=ok, severity="high" if ok else "",
                note="simulated", leaked_ids=list(self.leaked.get(c.endpoint_key, [])))
        return out
