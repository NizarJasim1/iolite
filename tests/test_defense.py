"""
defense — classify a real authz denial apart from a WAF/bot/challenge/expiry block, and learn
a per-host defence profile. The key precision guarantee for hardened targets.
"""
from iolite.intent.defense import (classify, Defense, DefenseProfile, is_authz_denial, is_block)


def test_clean_json_403_is_authz_not_waf():
    d, v = classify(403, {"content-type": "application/json"}, {"error": "forbidden"})
    assert d == Defense.FORBIDDEN_AUTHZ and is_authz_denial(d)


def test_waf_html_403_is_block_not_authz():
    d, v = classify(403, {"cf-ray": "abc", "server": "cloudflare"}, "Attention Required")
    assert d == Defense.WAF_BLOCK and v == "cloudflare" and not is_authz_denial(d) and is_block(d)


def test_rate_limited_and_challenge():
    assert classify(429, {"retry-after": "3"}, "slow down")[0] == Defense.RATE_LIMITED
    assert classify(503, {}, "Checking your browser recaptcha")[0] == Defense.CHALLENGE


def test_token_expiry_vs_plain_authn():
    assert classify(401, {}, {"error": "jwt expired"})[0] == Defense.AUTH_EXPIRED
    assert classify(401, {}, {"error": "unauthorized"})[0] == Defense.FORBIDDEN_AUTHZ


def test_vendor_fingerprints():
    assert classify(403, {"x-iinfo": "1"}, "blocked")[1] == "imperva/incapsula"
    assert classify(403, {"server": "AkamaiGHost"}, "denied")[1] == "akamai"


def test_profile_learns_safe_rate():
    p = DefenseProfile(host="h")
    for _ in range(3):
        p.update(Defense.OK, latency_ms=10, rate_now=4.0)
    p.update(Defense.RATE_LIMITED, rate_now=8.0, retry_after=2.0)
    assert p.first_block_rate == 8.0
    assert 0.2 <= p.safe_rate <= 8.0 and p.safe_rate < 8.0   # conservatively below the block rate
    assert p.rate_limited == 1 and p.retry_after_max == 2.0


def test_profile_counts_and_vendor():
    p = DefenseProfile(host="h")
    p.update(Defense.WAF_BLOCK, vendor="cloudflare", rate_now=5.0)
    p.update(Defense.AUTH_EXPIRED)
    s = p.summary()
    assert s["waf_blocks"] == 1 and s["vendor"] == "cloudflare" and s["auth_expired"] == 1
