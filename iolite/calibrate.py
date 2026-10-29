"""
Extraction calibration — MEASURE recall/precision, never claim it.

ONYX ships a labeled calibration; IOLITE must too, or its "deep extraction" claim
is unfalsifiable. This runs the miner against a labeled bundle whose true endpoint
set and asset decoys are known, and reports:

  * recall            — fraction of true endpoints recovered
  * asset_fp          — asset/static paths wrongly emitted (must be 0)
  * missed / extra    — the exact diffs, so a regression is visible

Deterministic and offline. `iolite selftest` runs it; `tests/test_calibration.py`
gates recall and asset-FP in CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .js_extract import extract_endpoints

_ASSET_MARKERS = ("/static/", "/assets/", ".css", ".png", ".js", "cdn.")


@dataclass
class Calibration:
    truth: set[str]
    found: set[str]
    recall: float
    missed: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    asset_fp: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.asset_fp

    def report(self) -> str:
        lines = [f"recall={self.recall:.3f}  ({len(self.found & self.truth)}/{len(self.truth)})",
                 f"asset false-positives={len(self.asset_fp)}"]
        if self.missed:
            lines.append("MISSED:")
            lines += [f"  - {m}" for m in self.missed]
        if self.asset_fp:
            lines.append("ASSET FP:")
            lines += [f"  ! {a}" for a in self.asset_fp]
        return "\n".join(lines)


def calibrate(js_text: str, truth: set[str],
              asset_markers=_ASSET_MARKERS) -> Calibration:
    found = {e.key for e in extract_endpoints(js_text, "calib")}
    hit = found & truth
    recall = len(hit) / len(truth) if truth else 1.0
    asset_fp = sorted(k for k in found if any(a in k for a in asset_markers))
    return Calibration(truth=truth, found=found, recall=recall,
                       missed=sorted(truth - found), extra=sorted(found - truth),
                       asset_fp=asset_fp)


# The ground truth for fixtures/calibration_bundle.js (human-labeled).
BUNDLE_TRUTH = {
    "GET /api/v1/orders/{id}",
    "POST /api/v1/orders/{id}/refund",
    "GET /api/v1/users/{id}/profile",
    "GET /api/v2/invoices/{id}",
    "DELETE /api/v1/admin/users",
    "POST /api/graphql",
}
