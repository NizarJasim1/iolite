"""
IOLITE Research — a target-selection engine that ranks live bug-bounty programs by
how well they FIT the IOLITE+ONYX toolchain, from PUBLIC data only (never a scan),
then closes the loop: it maps a chosen program's real scope onto the pipeline
(IOLITE stage → ONYX EffectClass → first move) and scaffolds a ready-to-run
engagement for `iolite go`.

Data source (community-maintained, refreshed ~every 30 min):
  https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/<platform>_data.json

What it scores (all from public program metadata — it never touches a target):
  FIT      mobile app in scope, API/GraphQL, wildcard, object-rich, breadth, severity
  AUTHZ    per-asset confidentiality=high (authorization/data-exposure prized → ONYX core),
           policy fine-print that welcomes IDOR/BOLA testing
  ANTI-LUCK  response efficiency %, fast first response, fast time-to-bounty
           (the operator's real fears — ghosting and slow pay — priced in from data)
  EDGE     🌱 uncrowded — a program not seen in your local ledger before (fewer hunters)

The score is a deterministic integer with a NAMED reason for every point (same
"prove, don't claim" discipline as ONYX triage). It RANKS; you read the policy and
decide. VDP/no-cash programs are dropped by default.

Modes (see cli.py):
  rank / report      best N targets, with tier (FOCUS / ROTATE / WATCH)
  plan(program)      the IOLITE→ONYX attack-surface map for one program
  scaffold(program)  a real engagement.json (RoE) for `iolite go` — stays dry-run
                     until YOU attest (legal-by-construction, QL1)
  ledger + diff_new  persistent uncrowded detection / brand-new-program watch
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from .roe import Engagement

RAW_BASE = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data"
PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy")

# Honest per-platform payout notes for an operator in Iraq. VERIFY on your own
# account before relying on it — sanctions / PayPal availability change and are
# account-specific. Crypto payout is usually the most Iraq-workable route.
PAYOUT_NOTES = {
    "hackerone": "PayPal / Coinbase (crypto). Iraq: PayPal not available — use CRYPTO (Coinbase/USDC). Verify.",
    "bugcrowd": "PayPal / Payoneer. Iraq: check Payoneer eligibility; PayPal usually unavailable. Verify.",
    "intigriti": "Bank transfer / PayPal. Iraq: bank wire may work; confirm with support. Verify.",
    "yeswehack": "Bank transfer / PayPal. Iraq: confirm bank wire with support. Verify.",
    "federacy": "Varies. Verify.",
}

# asset-type buckets (HackerOne asset_type vocabulary + heuristics)
_MOBILE = {"GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "OTHER_IPA",
           "TESTFLIGHT", "WINDOWS_APP_STORE_APP_ID"}
_APIISH = {"API", "GRAPHQL"}
_WILDCARD = {"WILDCARD"}
_WEB = {"URL", "CIDR", "IP_ADDRESS"}

# object-rich / multi-tenant signals, split by strength (weak words are near-universal
# and must not dominate the score; strong words really imply a deep object graph).
_RICH_STRONG = ("bank", "wallet", "payment", "fintech", "health", "hr", "crm", "erp",
                "tenant", "identity", "invoice", "order", "booking", "marketplace",
                "insurance", "broker", "ledger", "custody", "kyc")
_RICH_WEAK = ("saas", "platform", "workspace", "cloud", "portal", "dashboard", "account",
              "commerce", "ecommerce", "team", "org", "api", "app", "project", "ticket",
              "admin", "pay")

_APIID = re.compile(r"(?:^|[./-])(api|graphql|gql|rest|v\d+)(?:[./-]|$)", re.IGNORECASE)

# fine-print signals in an asset's `instruction` text
_AUTHZ_WELCOME = ("idor", "bola", "bfla", "broken object", "broken access",
                  "access control", "authorization", "authorisation",
                  "privilege escalation", "business logic")
_AUTOMATION_DENY = ("no automated", "automated scanning", "do not scan",
                    "automated tools are prohibited", "scanners are not",
                    "brute-forc", "brute forc")

# --------------------------------------------------------------------------- #
# capability map — the heart of the IOLITE+ONYX integration.                   #
# Each surface bucket → (IOLITE stage that mines it, ONYX EffectClasses it      #
# unlocks, the operator's first concrete move). Used by BOTH scoring reasons    #
# and plan().                                                                  #
# --------------------------------------------------------------------------- #
CAPABILITY = {
    "mobile": (
        "③ extract — mine the app's private/partner API from its own traffic",
        ("OBJECT_ACCESS", "BFLA/AUTHORITY"),
        "capture the mobile app's HTTPS traffic (your device) → iolite go --dir",
    ),
    "api": (
        "② HAR + ③ carrier extraction (path·query·header·JWT·GraphQL-var·body)",
        ("OBJECT_ACCESS", "CROSS_SURFACE"),
        "save one authenticated API request as HAR → iolite import-har",
    ),
    "wildcard": (
        "① passive OSINT + ④ temporal-diff (ghost & freshly-shipped endpoints)",
        ("EMERGENT_BREAK", "TEMPORAL_DRIFT"),
        "passively enumerate subdomains, snapshot, re-run later → iolite diff",
    ),
    "web": (
        "② HAR ingest + ③ JS/sourcemap mine",
        ("STATE_GATE", "OBJECT_ACCESS"),
        "record a HAR while logged in with two of YOUR accounts → iolite go --dir",
    ),
}


@dataclass
class Asset:
    ident: str
    atype: str
    bounty: bool = True
    max_sev: str = ""
    conf: str = ""                 # confidentiality_requirement: high/medium/low/…
    submittable: bool = True
    instruction: str = ""

    @property
    def bucket(self) -> str:
        t = (self.atype or "").upper()
        if t in _MOBILE:
            return "mobile"
        if t in _WILDCARD or "*" in self.ident:
            return "wildcard"
        if t in _APIISH or _APIID.search(self.ident or ""):
            return "api"
        if t in _WEB:
            return "web"
        return "other"

    @property
    def host(self) -> str | None:
        """Concrete host for scope/scaffold, or None for a non-host asset (mobile)."""
        if (self.atype or "").upper() in _MOBILE:
            return None
        s = (self.ident or "").strip()
        s = re.sub(r"^[a-zA-Z][\w+.-]*://", "", s)   # strip scheme
        s = s.split("@")[-1]                          # strip userinfo
        s = s.split("/", 1)[0].split("?", 1)[0]       # strip path/query
        s = s.rstrip(".")
        return s or None


@dataclass
class Program:
    platform: str
    name: str
    handle: str
    url: str
    website: str = ""
    paid: bool = False
    state: str = "open"
    assets: list[Asset] = field(default_factory=list)
    resp_hours: float | None = None       # average_time_to_first_program_response (hours)
    bounty_hours: float | None = None     # average_time_to_bounty_awarded (hours)
    resolve_hours: float | None = None    # average_time_to_report_resolved (hours)
    resp_eff: float | None = None         # response_efficiency_percentage (0-100)
    managed: bool = False
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    fresh: bool = False

    @property
    def key(self) -> str:
        return f"{self.platform}:{self.handle or self.url}"

    @property
    def tier(self) -> str:
        if self.score >= 45:
            return "FOCUS"
        if self.score >= 28:
            return "ROTATE"
        return "WATCH"


# --------------------------------------------------------------------------- #
# normalisation                                                               #
# --------------------------------------------------------------------------- #
def _assets(raw_targets) -> list[Asset]:
    out = []
    ins = (raw_targets or {}).get("in_scope") if isinstance(raw_targets, dict) else raw_targets
    for a in (ins or []):
        if not isinstance(a, dict):
            continue
        out.append(Asset(
            ident=str(a.get("asset_identifier") or a.get("target") or a.get("identifier") or ""),
            atype=str(a.get("asset_type") or a.get("type") or ""),
            bounty=bool(a.get("eligible_for_bounty", True)),
            max_sev=str(a.get("max_severity") or ""),
            conf=str(a.get("confidentiality_requirement") or ""),
            submittable=bool(a.get("eligible_for_submission", True)),
            instruction=str(a.get("instruction") or "")))
    return out


def _num(v):
    return v if isinstance(v, (int, float)) else None


def normalize(data, platform: str) -> list[Program]:
    """Parse a bounty-targets-data dump (list of programs) into Programs."""
    progs = data if isinstance(data, list) else (data.get("programs") if isinstance(data, dict) else [])
    out = []
    for p in progs or []:
        if not isinstance(p, dict):
            continue
        paid = bool(p.get("offers_bounties", p.get("bounty", p.get("max_payout", 0))))
        out.append(Program(
            platform=platform,
            name=str(p.get("name") or p.get("handle") or "?"),
            handle=str(p.get("handle") or p.get("id") or ""),
            url=str(p.get("url") or ""),
            website=str(p.get("website") or ""),
            paid=paid,
            state=str(p.get("submission_state") or "open"),
            assets=_assets(p.get("targets")),
            resp_hours=_num(p.get("average_time_to_first_program_response")),
            bounty_hours=_num(p.get("average_time_to_bounty_awarded")),
            resolve_hours=_num(p.get("average_time_to_report_resolved")),
            resp_eff=_num(p.get("response_efficiency_percentage")),
            managed=bool(p.get("managed_program", False))))
    return out


# --------------------------------------------------------------------------- #
# scoring — deterministic, transparent, capability- & reliability-aware        #
# --------------------------------------------------------------------------- #
def _instruction_flags(assets) -> tuple[bool, bool]:
    welcomes = restricts = False
    for a in assets:
        t = (a.instruction or "").lower()
        if not t:
            continue
        if any(k in t for k in _AUTHZ_WELCOME):
            welcomes = True
        if any(k in t for k in _AUTOMATION_DENY):
            restricts = True
    return welcomes, restricts


def score(p: Program, fresh_keys: frozenset[str] = frozenset()) -> None:
    s, why = 0, []
    buckets = {a.bucket for a in p.assets}
    n = len(p.assets)

    # gates
    if not p.paid:
        s -= 100
        why.append("-100 no bounties (VDP) — no cash")
    if p.state and p.state != "open":
        s -= 20
        why.append(f"-20 submissions {p.state}")

    # --- FIT: surface the toolchain is strongest at (reason names the ONYX class) ---
    for b in ("mobile", "api", "wildcard"):
        if b in buckets:
            pts = {"mobile": 12, "api": 10, "wildcard": 8}[b]
            _stage, effs, _mv = CAPABILITY[b]
            s += pts
            why.append(f"+{pts} {b} in scope → IOLITE {b}-mine → ONYX {'/'.join(effs)}")

    text = (p.name + " " + p.website + " " + p.url).lower()
    strong = sorted({w for w in _RICH_STRONG if w in text})
    weak = sorted({w for w in _RICH_WEAK if w in text})
    if strong:
        add = min(3 * len(strong), 9)
        s += add
        why.append(f"+{add} deep object-graph signals ({','.join(strong[:4])})")
    if weak:
        add = min(len(weak), 3)
        s += add
        why.append(f"+{add} object-rich hints ({','.join(weak[:4])})")

    if any(a.max_sev.lower() == "critical" for a in p.assets):
        s += 5
        why.append("+5 critical max-severity (high payout ceiling)")

    # --- AUTHZ sensitivity straight from the data (ONYX sweet spot) ---
    hi = sum(1 for a in p.assets if a.conf.lower() == "high")
    if hi:
        add = min(2 * hi, 6)
        s += add
        why.append(f"+{add} {hi} high-confidentiality asset(s) (authz/data-exposure prized)")

    welcomes, restricts = _instruction_flags(p.assets)
    if welcomes:
        s += 3
        why.append("+3 policy fine-print welcomes access-control/IDOR testing")
    if restricts:
        s -= 4
        why.append("-4 policy restricts automated testing — go slow / manual")

    # breadth
    if n:
        add = min(n // 5, 5)
        if add:
            s += add
            why.append(f"+{add} scope breadth ({n} assets)")

    # --- ANTI-LUCK: reliability & pay speed from public stats ---
    if p.resp_eff is not None:
        if p.resp_eff >= 90:
            s += 4
            why.append(f"+4 reliable responder ({p.resp_eff:.0f}% efficiency — low ghosting risk)")
        elif p.resp_eff >= 75:
            s += 2
            why.append(f"+2 responder ({p.resp_eff:.0f}% efficiency)")
        elif p.resp_eff < 50:
            s -= 3
            why.append(f"-3 unreliable responder ({p.resp_eff:.0f}% efficiency — ghosting risk)")
    if p.resp_hours is not None:
        if p.resp_hours <= 24:
            s += 3
            why.append(f"+3 fast first response (~{p.resp_hours:.0f}h)")
        elif p.resp_hours <= 72:
            s += 1
            why.append(f"+1 first response ~{p.resp_hours:.0f}h")
    if p.bounty_hours is not None:
        d = p.bounty_hours / 24.0
        if p.bounty_hours <= 168:
            s += 4
            why.append(f"+4 pays fast (~{d:.0f}d to bounty — good for cash flow)")
        elif p.bounty_hours <= 336:
            s += 2
            why.append(f"+2 pays in ~{d:.0f}d")
        elif p.bounty_hours > 2160:
            s -= 3
            why.append(f"-3 slow to pay (~{d:.0f}d to bounty)")

    # --- EDGE: uncrowded (newly seen in your ledger) ---
    if p.key in fresh_keys:
        p.fresh = True
        s += 10
        why.append("+10 🌱 uncrowded — new since your last run (fewer hunters yet)")

    p.score, p.reasons = s, why


def rank(programs: list[Program], top: int = 5, paid_only: bool = True,
         fresh_keys: frozenset[str] = frozenset()) -> list[Program]:
    for p in programs:
        score(p, fresh_keys)
    pool = [p for p in programs if (p.paid or not paid_only) and p.state == "open"]
    # tiebreak: score, then reliability, then faster pay, then name — deterministic
    pool.sort(key=lambda p: (-p.score, -(p.resp_eff or 0),
                             (p.bounty_hours if p.bounty_hours is not None else 1e9),
                             p.name.lower()))
    return pool[:max(0, top)]


def diff_new(old: list[Program], new: list[Program]) -> list[Program]:
    """Programs present in `new` but not `old` — brand-new targets to hit first."""
    seen = {p.key for p in old}
    fresh = [p for p in new if p.key not in seen]
    fkeys = frozenset(p.key for p in fresh)
    for p in fresh:
        score(p, fkeys)
    fresh.sort(key=lambda p: (-p.score, p.name.lower()))
    return fresh


def find(programs: list[Program], handle: str) -> Program | None:
    h = (handle or "").strip().lower()
    for p in programs:
        if p.handle.lower() == h or p.name.lower() == h or p.key.lower().endswith(":" + h):
            return p
    return None


# --------------------------------------------------------------------------- #
# integration — map a program onto the IOLITE→ONYX pipeline, scaffold the RoE  #
# --------------------------------------------------------------------------- #
def hosts_of(p: Program) -> list[str]:
    out = []
    for a in p.assets:
        if not a.bounty:
            continue
        h = a.host
        if h and h not in out:
            out.append(h)
    return out


def mobile_targets(p: Program) -> list[str]:
    return [a.ident for a in p.assets if a.bucket == "mobile" and a.bounty]


def plan(p: Program) -> str:
    """The IOLITE→ONYX attack-surface map for one program (no packets sent)."""
    L = [f"IOLITE→ONYX surface plan — {p.name} ({p.platform})  [{p.tier}, score {p.score}]",
         f"  scope page: {p.url}", ""]
    order = ["mobile", "api", "wildcard", "web"]
    present = [b for b in order if any(a.bucket == b for a in p.assets)]
    if not present:
        L.append("  (no mobile/api/wildcard/web assets recognised — read the policy manually)")
    for b in present:
        stage, effs, move = CAPABILITY[b]
        idents = [a.ident for a in p.assets if a.bucket == b and a.bounty][:4]
        L.append(f"  [{b.upper()}]  {idents}")
        L.append(f"     IOLITE:  {stage}")
        L.append(f"     ONYX:    proves {', '.join(effs)}")
        L.append(f"     first move: {move}")
        L.append("")
    hi = [a.ident for a in p.assets if a.conf.lower() == "high"][:5]
    if hi:
        L.append(f"  ⭑ high-confidentiality assets (authz Δstate goldmine): {hi}")
    L.append("  Then: iolite go --dir ./captures  → verifies with ONYX → spec.json (proof).")
    L.append("  Reminder: only YOUR accounts for cross-principal proofs; read the policy first.")
    return "\n".join(L)


def scaffold(p: Program) -> Engagement:
    """A ready-to-edit engagement (RoE) for `iolite go`, seeded from the program's
    REAL public scope. It stays dry-run/offline until YOU write an attestation
    (attested()==False by design → legal-by-construction, QL1)."""
    return Engagement(
        program=f"{p.name} ({p.platform})",
        authorized_by=p.url or p.website,     # the public scope page is the basis…
        operator="",                          # …but YOU must fill this and attest below
        in_scope_hosts=hosts_of(p),
        out_of_scope_hosts=[],                # copy the program's out-of-scope list here
        automation_permitted=False,
        allow_destructive=False,
        dry_run=True,
        own_accounts_only=True,
        max_requests_per_min=30,
        attestation="")                       # BLANK ⇒ not attested ⇒ no live requests yet


# --------------------------------------------------------------------------- #
# persistent uncrowded ledger                                                  #
# --------------------------------------------------------------------------- #
def load_ledger(path: str) -> set[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return set(d.get("seen", [])) if isinstance(d, dict) else set(d or [])
    except (OSError, ValueError):
        return set()


def save_ledger(path: str, programs: list[Program]) -> None:
    seen = sorted(set(load_ledger(path)) | {p.key for p in programs})
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"seen": seen}, fh, indent=0)


# --------------------------------------------------------------------------- #
# IO — offline file + live GitHub fetch (network; run on your machine)         #
# --------------------------------------------------------------------------- #
def load_file(path: str, platform: str | None = None) -> list[Program]:
    plat = platform or _platform_from_name(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return normalize(json.load(fh), plat)


def fetch_live(platform: str, timeout: int = 60) -> list[Program]:  # pragma: no cover - network
    import urllib.request
    url = f"{RAW_BASE}/{platform}_data.json"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return normalize(json.loads(r.read()), platform)


def _platform_from_name(path: str) -> str:
    low = path.lower()
    for pl in PLATFORMS:
        if pl in low:
            return pl
    return "unknown"


# --------------------------------------------------------------------------- #
# rendering                                                                    #
# --------------------------------------------------------------------------- #
def report(programs: list[Program]) -> str:
    L = ["IOLITE Research — best targets for your toolchain (public data only)\n"]
    for i, p in enumerate(programs, 1):
        buckets = sorted({a.bucket for a in p.assets if a.bucket != "other"})
        flag = " 🌱NEW" if p.fresh else ""
        L.append(f"{i}. [{p.score:>3}] [{p.tier}]{flag} {p.name}  ({p.platform})")
        L.append(f"     {p.url}")
        L.append(f"     scope: {', '.join(buckets) or 'n/a'} · {len(p.assets)} assets · "
                 f"{'PAID' if p.paid else 'VDP'}"
                 + (f" · {p.resp_eff:.0f}% responsive" if p.resp_eff is not None else "")
                 + (f" · ~{p.bounty_hours / 24:.0f}d pay" if p.bounty_hours is not None else ""))
        L.append("     why: " + "; ".join(r.split(' ', 1)[1] for r in p.reasons[:4]))
        L.append(f"     next: iolite research --plan {p.handle}   (IOLITE→ONYX surface map)")
        L.append(f"     payout({p.platform}): {PAYOUT_NOTES.get(p.platform, 'verify')}")
        L.append("")
    L.append("Tiers: FOCUS ≥45 · ROTATE ≥28 · WATCH <28. PUBLIC data only — "
             "read each program's policy & scope before testing.")
    return "\n".join(L)
