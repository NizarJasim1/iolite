"""
IOLITE — the legal deep authorization-surface acquisition engine.

The recon companion that feeds ONYX/AuthPath: it mines the deepest surface a target
legally exposes, models it, ranks it by authorization risk, and emits an
ONYX-compatible spec.json. It never adjudicates — ONYX's Δstate confirmer owns the
verdict (QL5).
"""

__version__ = "1.29.0"

from .models import (Effect, Endpoint, Principal, Provenance, SourceKind,
                     EvidenceTier, SurfaceModel, ObservedAccess)
from .scope_guard import ScopeConfig, ScopeGuard, ScopeVerdict
from .roe import Engagement
from .pipeline import Inputs, run, Result
from .preflight import preflight, PreflightReport, Gate
from .live_calibrate import calibrate_from_samples, is_sound_delta, StabilityProfile

__all__ = [
    "Effect", "Endpoint", "Principal", "Provenance", "SourceKind", "EvidenceTier",
    "SurfaceModel", "ObservedAccess", "ScopeConfig", "ScopeGuard", "ScopeVerdict",
    "Engagement", "Inputs", "run", "Result",
    "preflight", "PreflightReport", "Gate",
    "calibrate_from_samples", "is_sound_delta", "StabilityProfile", "__version__",
]
