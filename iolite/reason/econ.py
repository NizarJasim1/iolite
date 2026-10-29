"""
reason · econ — the measured operating ledger. "Low-luck income" is a STATISTICAL
property, not a per-bug hope: it emerges from always working the highest realized-EV
program and reallocating away from the rest. This ledger measures the only truth that
matters — realized $/hour and acceptance rate per program — and recommends
FOCUS / ROTATE / DROP, with a bounded exploration nudge for un-tried programs.

Measured facts, never prediction (QL3). Deterministic (QL4). Serves goals 2 & 5.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict

_PAID = "paid"
_STATUSES = ("paid", "duplicate", "informational", "not-applicable", "out-of-scope",
             "pending", "triaging")


@dataclass
class EconEntry:
    program: str
    status: str = "pending"            # one of _STATUSES
    payout: float = 0.0                # USD (or crypto-equivalent) actually received
    hours: float = 0.0                 # hours spent producing this submission
    finding: str = ""                  # short label / cand_key
    date: str = ""                     # optional ISO date (operator-supplied)


def load_ledger(path: str) -> list[EconEntry]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return []
    out = []
    for r in raw if isinstance(raw, list) else []:
        if isinstance(r, dict) and r.get("program"):
            out.append(EconEntry(**{k: r.get(k, getattr(EconEntry, k, "")) for k in
                                    ("program", "status", "payout", "hours", "finding", "date")}))
    return out


def save_ledger(path: str, entries: list[EconEntry]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(e) for e in entries], fh, indent=2, sort_keys=True)


@dataclass
class ProgramStats:
    program: str
    submissions: int = 0
    paid: int = 0
    duplicate: int = 0
    dead: int = 0                      # informational / n-a / out-of-scope
    dollars: float = 0.0
    hours: float = 0.0

    @property
    def dollars_per_hour(self) -> float:
        return round(self.dollars / self.hours, 2) if self.hours > 0 else 0.0

    @property
    def acceptance_rate(self) -> float:
        decided = self.paid + self.duplicate + self.dead
        return round(self.paid / decided, 3) if decided > 0 else 0.0

    @property
    def dup_rate(self) -> float:
        decided = self.paid + self.duplicate + self.dead
        return round(self.duplicate / decided, 3) if decided > 0 else 0.0


def program_stats(entries: list[EconEntry]) -> dict[str, ProgramStats]:
    out: dict[str, ProgramStats] = {}
    for e in entries:
        st = out.setdefault(e.program, ProgramStats(program=e.program))
        st.submissions += 1
        st.hours += max(0.0, e.hours)
        if e.status == "paid":
            st.paid += 1
            st.dollars += max(0.0, e.payout)
        elif e.status == "duplicate":
            st.duplicate += 1
        elif e.status in ("informational", "not-applicable", "out-of-scope"):
            st.dead += 1
    return dict(sorted(out.items()))


@dataclass
class Recommendation:
    program: str
    action: str                        # FOCUS | ROTATE | DROP | EXPLORE
    dollars_per_hour: float
    acceptance_rate: float
    reason: str


def recommend(stats: dict[str, ProgramStats], min_samples: int = 3,
              focus_dph: float = 50.0, drop_dph: float = 10.0) -> list[Recommendation]:
    """Deterministic FOCUS/ROTATE/DROP + EXPLORE. A program with too few decided
    submissions is EXPLORE (bounded exploration), never prematurely dropped."""
    out: list[Recommendation] = []
    for prog in sorted(stats):
        st = stats[prog]
        decided = st.paid + st.duplicate + st.dead
        dph, acc = st.dollars_per_hour, st.acceptance_rate
        if decided < min_samples:
            action, why = "EXPLORE", (f"only {decided} decided submission(s) — too few to judge; "
                                      f"invest a bounded amount to learn its $/hr")
        elif dph >= focus_dph and acc >= 0.25:
            action, why = "FOCUS", f"realized ${dph}/hr, acceptance {acc} — your edge pays here"
        elif dph <= drop_dph or acc < 0.1:
            action, why = "DROP", (f"realized ${dph}/hr, acceptance {acc}, dup-rate {st.dup_rate} "
                                   f"— reallocate the hours")
        else:
            action, why = "ROTATE", f"middling (${dph}/hr, acc {acc}) — keep only if nothing better"
        out.append(Recommendation(prog, action, dph, acc, why))
    # deterministic ranking: FOCUS first, then by $/hr desc, then name
    order = {"FOCUS": 0, "EXPLORE": 1, "ROTATE": 2, "DROP": 3}
    out.sort(key=lambda r: (order.get(r.action, 9), -r.dollars_per_hour, r.program))
    return out


def portfolio_summary(entries: list[EconEntry]) -> dict:
    stats = program_stats(entries)
    tot_h = sum(s.hours for s in stats.values())
    tot_d = sum(s.dollars for s in stats.values())
    return {
        "programs": len(stats),
        "submissions": sum(s.submissions for s in stats.values()),
        "paid": sum(s.paid for s in stats.values()),
        "dollars": round(tot_d, 2),
        "hours": round(tot_h, 2),
        "blended_dollars_per_hour": round(tot_d / tot_h, 2) if tot_h > 0 else 0.0,
        "recommendations": [asdict(r) for r in recommend(stats)],
    }
