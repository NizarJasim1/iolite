"""
defense.py — sense and LEARN the target's defences, and tell a real authz denial apart from
a defensive block.

The strongest programs sit behind WAFs, bot-management and rate limiters. Two problems follow
for an authz tool: (1) blindly hammering gets you blocked or banned, and (2) a WAF/bot 403 is
NOT an authorization boundary — mistaking it for one both wastes effort and corrupts the intent
model. This module classifies every response into a DEFENCE signal and maintains a per-host
`DefenseProfile` learned online (safe rate, latency baseline, block patterns, vendor), which the
pacer/executor use to go as fast as the target tolerates and no faster.

Classification is deliberately conservative: a 403/401 is treated as a true authz/authn denial
ONLY when it carries no WAF/bot/challenge fingerprint and no token-expiry marker. Pure-stdlib,
deterministic (QL4).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Defense(str, Enum):
    OK = "OK"
    RATE_LIMITED = "RATE_LIMITED"      # 429 / Retry-After
    WAF_BLOCK = "WAF_BLOCK"            # edge/bot block (not authz)
    CHALLENGE = "CHALLENGE"            # captcha / JS challenge / interstitial
    AUTH_EXPIRED = "AUTH_EXPIRED"      # token/session expired (re-auth, not authz)
    SERVER_ERROR = "SERVER_ERROR"      # 5xx
    FORBIDDEN_AUTHZ = "FORBIDDEN_AUTHZ"  # a CLEAN 403/401 — a real authorization/authn denial
    NOT_FOUND = "NOT_FOUND"            # 404 (may mask authz)
    CLIENT_ERROR = "CLIENT_ERROR"
    OTHER = "OTHER"


# vendor fingerprints (headers or body substrings), lower-cased
_WAF = {
    "cloudflare": ("cf-ray", "cloudflare", "__cf", "cf-mitigated"),
    "akamai": ("akamai", "akamaighost", "x-akamai", "ak-"),
    "imperva/incapsula": ("incapsula", "imperva", "x-iinfo", "visid_incap", "x-cdn"),
    "aws-waf": ("awswaf", "x-amzn-waf", "x-amzn-requestid"),
    "sucuri": ("sucuri", "x-sucuri-id"),
    "f5-bigip": ("bigip", "x-waf", "f5"),
    "datadome": ("datadome", "x-datadome"),
    "perimeterx/human": ("perimeterx", "_px", "px-", "human challenge"),
    "modsecurity": ("mod_security", "modsecurity", "not acceptable"),
    "distil": ("distil",),
}
_BLOCK_BODY = ("request blocked", "access denied", "attention required", "you have been blocked",
               "blocked by", "bot detected", "request unsuccessful", "reference #",
               "this request was blocked", "unusual traffic")
_CHALLENGE = ("captcha", "recaptcha", "hcaptcha", "js challenge", "checking your browser",
              "enable javascript", "are you human", "__cf_chl", "challenge-platform", "px-captcha")
_EXPIRED = ("token expired", "jwt expired", "token is expired", "invalid_token", "session expired",
            "expired token", "credentials expired", "token has expired", "expired jwt")


def _header_hay(headers: dict | None) -> str:
    return " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()


def _body_text(body) -> str:
    """Only a STRING body (an HTML/text block page) is treated as prose for block-phrase
    matching. A structured JSON object/array is a legit API payload, not a WAF page — so a
    clean `{\"error\":\"forbidden\"}` is never mistaken for a block."""
    return body[:4000].lower() if isinstance(body, str) else ""


def _waf_vendor(hay: str) -> str:
    for vendor, marks in _WAF.items():
        if any(m in hay for m in marks):
            return vendor
    return ""


def classify(status: int, headers: dict | None = None, body=None) -> tuple[str, str]:
    """Return (Defense, vendor). Conservative: a 403/401 is FORBIDDEN_AUTHZ unless it carries a
    vendor fingerprint (headers), a block phrase (text body only), or a challenge marker."""
    hhay = _header_hay(headers)
    btxt = _body_text(body)
    vendor = _waf_vendor(hhay + " " + btxt)
    challenge = any(m in hhay or m in btxt for m in _CHALLENGE)
    block_body = any(m in btxt for m in _BLOCK_BODY)
    hay = hhay + " " + btxt      # for expiry markers (may be in a JSON error too)
    if isinstance(body, (dict, list)):
        hay += " " + str(body)[:2000].lower()

    if status == 429:
        return (Defense.RATE_LIMITED, vendor)
    if status in (503, 520, 521, 522, 526) or (challenge and status in (403, 429, 503)):
        return (Defense.CHALLENGE if challenge else Defense.SERVER_ERROR, vendor)
    if status == 401:
        return (Defense.AUTH_EXPIRED if any(m in hay for m in _EXPIRED) else Defense.FORBIDDEN_AUTHZ, vendor)
    if status in (403, 406):
        if vendor or block_body or challenge:
            return (Defense.CHALLENGE if challenge else Defense.WAF_BLOCK, vendor)
        return (Defense.FORBIDDEN_AUTHZ, vendor)
    if status == 404:
        return (Defense.NOT_FOUND, vendor)
    if 500 <= status < 600:
        return (Defense.SERVER_ERROR, vendor)
    if 200 <= status < 300:
        return (Defense.OK, vendor)
    if 400 <= status < 500:
        return (Defense.CLIENT_ERROR, vendor)
    return (Defense.OTHER, vendor)


_HARD_BLOCK = {Defense.RATE_LIMITED, Defense.WAF_BLOCK, Defense.CHALLENGE, Defense.SERVER_ERROR}


def is_authz_denial(d: str) -> bool:
    """Only a clean 403/401 teaches an authorization boundary."""
    return d == Defense.FORBIDDEN_AUTHZ


def is_block(d: str) -> bool:
    return d in _HARD_BLOCK


@dataclass
class DefenseProfile:
    """Per-host, learned online. The pacer reads `safe_rate`; the intent learner reads the
    classification to exclude defensive denials. Serializable (carry across runs)."""
    host: str = ""
    requests: int = 0
    ok: int = 0
    blocks: int = 0
    rate_limited: int = 0
    challenges: int = 0
    waf_blocks: int = 0
    auth_expired: int = 0
    vendor: str = ""
    latency_ewma_ms: float = 0.0
    # learned pacing: the highest sustained rate seen with no block, and the rate at first block
    max_ok_rate: float = 0.0
    first_block_rate: float = 0.0
    retry_after_max: float = 0.0

    def update(self, d: str, *, vendor: str = "", latency_ms: float = 0.0,
               rate_now: float = 0.0, retry_after: float = 0.0) -> None:
        self.requests += 1
        if vendor and not self.vendor:
            self.vendor = vendor
        if latency_ms > 0:
            self.latency_ewma_ms = (0.8 * self.latency_ewma_ms + 0.2 * latency_ms
                                    if self.latency_ewma_ms else latency_ms)
        if d == Defense.OK:
            self.ok += 1
            self.max_ok_rate = max(self.max_ok_rate, rate_now)
        elif is_block(d):
            self.blocks += 1
            if rate_now and (not self.first_block_rate or rate_now < self.first_block_rate):
                self.first_block_rate = rate_now
            if d == Defense.RATE_LIMITED:
                self.rate_limited += 1
            elif d == Defense.WAF_BLOCK:
                self.waf_blocks += 1
            elif d == Defense.CHALLENGE:
                self.challenges += 1
            if retry_after:
                self.retry_after_max = max(self.retry_after_max, retry_after)
        elif d == Defense.AUTH_EXPIRED:
            self.auth_expired += 1

    @property
    def safe_rate(self) -> float:
        """A conservative sustainable rate (req/s): just under the first observed block, or the
        best clean rate seen, defaulting low until evidence exists."""
        if self.first_block_rate:
            return max(0.2, 0.75 * self.first_block_rate)
        if self.max_ok_rate:
            return self.max_ok_rate
        return 2.0

    def summary(self) -> dict:
        return {"host": self.host, "vendor": self.vendor, "requests": self.requests,
                "ok": self.ok, "blocks": self.blocks, "rate_limited": self.rate_limited,
                "waf_blocks": self.waf_blocks, "challenges": self.challenges,
                "auth_expired": self.auth_expired, "safe_rate": round(self.safe_rate, 2),
                "latency_ewma_ms": round(self.latency_ewma_ms, 1)}
