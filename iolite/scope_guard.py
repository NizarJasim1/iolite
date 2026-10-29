"""
⓪ Scope-Guard (QL1) — legal boundary, fail-safe to inaction.

v0.4 — hardened for REAL programs and against adversarial host tricks:

  * wildcard scope        `*.example.com`  matches the apex + any subdomain, anchored
                          on a dot boundary (so `example.com.evil.net`, `notexample.com`
                          and `evilexample.com` are REJECTED)
  * subdomains-only       `.example.com`   matches subdomains but NOT the apex
  * exact                 `api.example.com`
  * out-of-scope wins     a host matching any denied pattern HALTs even if it also
                          matches an in-scope wildcard (`*.x.com` except `internal.x.com`)
  * normalisation         scheme / userinfo / port / path / trailing-dot stripped;
                          IDN → punycode (defeats homograph lookalikes); IPv6 kept

Any uncertainty resolves to HALT. Nothing in IOLITE emits a request-bearing plan
without a prior ALLOW here. The emitted spec carries CONCRETE hosts (see onyx_spec),
never wildcard patterns, so ONYX enforces on real hosts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ScopeVerdict(str, Enum):
    ALLOW = "ALLOW"
    HALT = "HALT"


@dataclass
class ScopeDecision:
    verdict: ScopeVerdict
    reason: str
    host: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict is ScopeVerdict.ALLOW


@dataclass
class ScopeConfig:
    """Technical scope. `allowed_hosts`/`denied_hosts` may contain wildcard patterns
    (IOLITE-internal). `to_spec()` emits only the ONYX-compatible flag fields; the
    concrete allowed hosts for the spec are resolved by onyx_spec from what was seen."""
    allowed_hosts: list[str] = field(default_factory=list)
    denied_hosts: list[str] = field(default_factory=list)
    dry_run: bool = True
    automation_permitted: bool = False
    allow_destructive: bool = False

    def to_spec(self, resolved_hosts=None) -> dict:
        # only NON-wildcard allowed entries are safe to hand ONYX verbatim; prefer
        # the concrete resolved hosts when provided.
        if resolved_hosts is None:
            resolved_hosts = [h for h in self.allowed_hosts if "*" not in h]
        return {
            "allowed_hosts": sorted(set(_normalize(h) for h in resolved_hosts if h)),
            "dry_run": bool(self.dry_run),
            "automation_permitted": bool(self.automation_permitted),
            "allow_destructive": bool(self.allow_destructive),
        }


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _normalize(host: str) -> str:
    """Canonicalise a host: lowercase, strip scheme/userinfo/port/path/trailing dot,
    IDN→punycode. IPv6 literals are preserved in bracket form."""
    if not host:
        return ""
    h = host.strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    if "@" in h:
        h = h.rsplit("@", 1)[1]                 # strip userinfo (user:pass@)
    h = h.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if h.startswith("["):                        # IPv6 literal [::1]:8080
        end = h.find("]")
        return h[:end + 1] if end != -1 else h
    h = h.split(":", 1)[0]                        # strip port
    h = h.rstrip(".")                             # trailing dot
    try:
        h = h.encode("idna").decode("ascii")      # homograph / unicode defence
    except Exception:
        pass
    return h


def _match(pattern: str, host: str) -> bool:
    """host is already normalised. pattern may be exact / `*.base` / `.base`."""
    p = pattern.strip().lower().rstrip(".")
    if p.startswith("*."):
        base = _normalize(p[2:])
        return bool(base) and (host == base or host.endswith("." + base))
    if p.startswith("."):
        base = _normalize(p[1:])
        return bool(base) and host.endswith("." + base)
    return host == _normalize(p)


class ScopeGuard:
    def __init__(self, config: ScopeConfig):
        self.config = config
        self.allowed = [p for p in config.allowed_hosts if p]
        self.denied = [p for p in config.denied_hosts if p]

    def check_host(self, host: str) -> ScopeDecision:
        h = _normalize(host)
        if not h:
            return ScopeDecision(ScopeVerdict.HALT, "empty host — fail-safe", host)
        # out-of-scope wins, always
        for d in self.denied:
            if _match(d, h):
                return ScopeDecision(ScopeVerdict.HALT, f"host matches out-of-scope '{d}'", h)
        if not self.allowed:
            return ScopeDecision(ScopeVerdict.HALT,
                                 "no allow-list declared — fail-safe to inaction", h)
        for a in self.allowed:
            if _match(a, h):
                return ScopeDecision(ScopeVerdict.ALLOW, f"host in scope via '{a}'", h)
        return ScopeDecision(ScopeVerdict.HALT, "host not in declared scope", h)

    def check_probe(self, host: str, method: str) -> ScopeDecision:
        host_dec = self.check_host(host)
        if not host_dec.allowed:
            return host_dec
        if not self.config.automation_permitted:
            return ScopeDecision(ScopeVerdict.HALT,
                                 "automation not permitted by the engagement", host)
        m = (method or "GET").upper()
        if m not in _SAFE_METHODS and not (self.config.allow_destructive and not self.config.dry_run):
            return ScopeDecision(ScopeVerdict.HALT,
                                 f"mutating method {m} blocked (dry_run/allow_destructive)", host)
        return ScopeDecision(ScopeVerdict.ALLOW, "probe within scope", host)

    def filter_hosts(self, hosts) -> list[str]:
        return sorted({_normalize(h) for h in hosts if self.check_host(h).allowed})
