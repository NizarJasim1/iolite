"""Extraction calibration gate — recall and zero asset false-positives."""
import os

from iolite.calibrate import calibrate, BUNDLE_TRUTH

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


def _bundle():
    with open(os.path.join(_FIX, "calibration_bundle.js"), encoding="utf-8") as fh:
        return fh.read()


def test_recall_meets_bar():
    cal = calibrate(_bundle(), BUNDLE_TRUTH)
    assert cal.recall >= 0.9, f"recall {cal.recall:.3f} below bar\n{cal.report()}"


def test_zero_asset_false_positives():
    cal = calibrate(_bundle(), BUNDLE_TRUTH)
    assert cal.clean, f"asset FP leaked:\n{cal.report()}"


def test_concat_and_template_patterns_recovered():
    cal = calibrate(_bundle(), BUNDLE_TRUTH)
    # the patterns the old miner missed must now be present
    for key in ("GET /api/v1/orders/{id}",             # template literal
                "POST /api/v1/orders/{id}/refund",     # multi-part concat
                "GET /api/v2/invoices/{id}"):          # const-prefixed
        assert key in cal.found, f"{key} not recovered\n{cal.report()}"


def test_deterministic():
    a = calibrate(_bundle(), BUNDLE_TRUTH).found
    b = calibrate(_bundle(), BUNDLE_TRUTH).found
    assert a == b
