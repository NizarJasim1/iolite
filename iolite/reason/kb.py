"""
reason · kb — cross-session program knowledge. It makes the operation COMPOUND
instead of restarting cold each session, and it produces the two highest-EV
collision signals:

  * FRESH endpoint   — a key never seen in prior sessions ⇒ fewer prior hunters.
  * REGRESSION       — a declared guard that EXISTED last session and is GONE now ⇒
                       a freshly-introduced bug (very low collision + high validity).

Stored knowledge is measured fact (which keys/guards were seen), never prediction.
Deterministic (QL4). Additive — the engine runs without a KB; it only sharpens EV.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class KB:
    programs: dict = field(default_factory=dict)   # program -> {"endpoints": {key:{"rank":int}}, "guards":[str]}

    def program(self, name: str) -> dict:
        return self.programs.get(name, {"endpoints": {}, "guards": []})


def load_kb(path: str) -> KB:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        if isinstance(raw, dict) and isinstance(raw.get("programs"), dict):
            return KB(programs=raw["programs"])
    except (OSError, ValueError):
        pass
    return KB()


def save_kb(path: str, kb: KB) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"programs": kb.programs}, fh, indent=2, sort_keys=True)


def fresh_endpoints(prior: dict, intent: dict) -> list[str]:
    """Keys present now but not in the prior snapshot (deterministic, sorted)."""
    seen = set((prior or {}).get("endpoints", {}))
    return sorted(k for k in intent if k not in seen)


def regressions(prior: dict, guards_now) -> list[str]:
    """Declared gate-predicates that existed last session and are ABSENT now — a
    guard that weakened ⇒ a freshly-introduced bug. Sorted, deterministic."""
    now = {g.gate_predicate for g in (guards_now or [])}
    return sorted(p for p in (prior or {}).get("guards", []) if p not in now)


def kb_signals(prior: dict, intent: dict, guards_now) -> dict:
    """Per-collision signals derived from the prior snapshot:
        {"fresh": set[endpoint_key], "regressed_objects": set[str]}."""
    fresh = set(fresh_endpoints(prior, intent))
    gone = regressions(prior, guards_now)
    regressed_objects = set()
    for pred in gone:
        # a gate predicate is "field==value" / "not(field==value)"; the object token
        # is not in the predicate, so mark by field+value for loose endpoint matching
        regressed_objects.add(pred.split("==")[0].strip("not( ").lower())
    return {"fresh": fresh, "regressed_objects": regressed_objects, "regressions": gone}


def update_from(kb: KB, program: str, intent: dict, guards_now=None) -> KB:
    """Merge this session's surface + declared guards into the KB (monotone union of
    keys; guard set replaced by the current one so a future session can detect a drop)."""
    prog = kb.programs.setdefault(program, {"endpoints": {}, "guards": []})
    eps = prog.setdefault("endpoints", {})
    for key, rule in intent.items():
        cur = eps.get(key, {})
        eps[key] = {"rank": max(int(cur.get("rank", -1)), int(getattr(rule, "rank", -1)))}
    prog["endpoints"] = dict(sorted(eps.items()))
    prog["guards"] = sorted({g.gate_predicate for g in (guards_now or [])})
    kb.programs = dict(sorted(kb.programs.items()))
    return kb
