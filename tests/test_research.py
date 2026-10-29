"""Research engine — rank programs by fit for the IOLITE+ONYX toolchain."""
import os

from iolite import research

_FIX = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
_SAMPLE = os.path.join(_FIX, "research_sample.json")


def _progs():
    return research.load_file(_SAMPLE, platform="hackerone")


def test_loads_and_normalises():
    progs = _progs()
    assert len(progs) == 4
    acme = [p for p in progs if p.handle == "acme_cloud"][0]
    buckets = {a.bucket for a in acme.assets}
    assert "mobile" in buckets and "wildcard" in buckets and "api" in buckets
    # richer fields parsed
    assert acme.resp_eff == 96.0 and acme.bounty_hours == 120.0 and acme.managed is True
    assert any(a.conf == "high" for a in acme.assets)


def test_ranks_rich_paid_program_first():
    top = research.rank(_progs(), top=5)
    assert top[0].handle in ("acme_cloud", "delta_wallet")   # rich + paid
    names = [p.handle for p in top]
    assert names.index("acme_cloud") < names.index("bob_blog")


def test_acme_is_focus_tier():
    acme = research.rank(_progs(), top=1)[0]
    assert acme.handle == "acme_cloud" and acme.tier == "FOCUS" and acme.score >= 45


def test_vdp_excluded_by_default():
    top = research.rank(_progs(), top=10)
    assert all(p.paid for p in top)
    assert "charlie_vdp" not in {p.handle for p in top}


def test_vdp_included_when_asked():
    top = research.rank(_progs(), top=10, paid_only=False)
    assert "charlie_vdp" in {p.handle for p in top}


def test_reasons_are_transparent():
    top = research.rank(_progs(), top=1)
    assert top[0].reasons and any("mobile" in r or "API" in r for r in top[0].reasons)


def test_reliability_and_payspeed_scored():
    progs = _progs()
    research.rank(progs, top=5)
    acme = research.find(progs, "acme_cloud")
    delta = research.find(progs, "delta_wallet")
    # acme: 96% + fast pay ⇒ positive reliability reasons
    assert any("reliable responder" in r for r in acme.reasons)
    assert any("pays fast" in r for r in acme.reasons)
    # delta: 62% + very slow pay ⇒ penalised, so it ranks BELOW acme
    assert any("slow to pay" in r for r in delta.reasons)
    assert acme.score > delta.score


def test_confidentiality_and_fineprint_scored():
    acme = research.rank(_progs(), top=1)[0]
    assert any("high-confidentiality" in r for r in acme.reasons)
    assert any("welcomes access-control/IDOR" in r for r in acme.reasons)


def test_deterministic():
    a = [p.key for p in research.rank(_progs(), top=5)]
    b = [p.key for p in research.rank(_progs(), top=5)]
    assert a == b


def test_watch_detects_new_programs():
    old = [p for p in _progs() if p.handle != "delta_wallet"]   # pretend delta is new
    new = _progs()
    fresh = research.diff_new(old, new)
    assert [p.handle for p in fresh] == ["delta_wallet"]


def test_fresh_bonus_promotes_uncrowded():
    progs = _progs()
    base = {p.handle: p.score for p in research.rank(progs, top=5)}
    fkeys = frozenset([research.find(progs, "bob_blog").key])
    boosted = research.rank(_progs(), top=5, fresh_keys=fkeys)
    bob = research.find(boosted, "bob_blog")
    assert bob.fresh and bob.score == base["bob_blog"] + 10
    assert any("uncrowded" in r for r in bob.reasons)


def test_ledger_roundtrip(tmp_path=None):
    import tempfile
    d = tempfile.mkdtemp()
    led = os.path.join(d, "seen.json")
    assert research.load_ledger(led) == set()          # missing file → empty
    progs = _progs()
    research.save_ledger(led, progs)
    seen = research.load_ledger(led)
    assert {p.key for p in progs} <= seen and len(seen) == 4


def test_plan_maps_iolite_to_onyx():
    acme = research.find(_progs(), "acme_cloud")
    txt = research.plan(acme)
    assert "IOLITE→ONYX surface plan" in txt
    assert "MOBILE" in txt and "OBJECT_ACCESS" in txt
    assert "high-confidentiality" in txt and "iolite go" in txt


def test_scaffold_builds_engagement_from_real_scope():
    acme = research.find(_progs(), "acme_cloud")
    eng = research.scaffold(acme)
    hosts = set(eng.in_scope_hosts)
    assert "app.acme.com" in hosts and "api.acme.com" in hosts   # path stripped
    assert "*.acme.com" in hosts                                 # wildcard kept for scope-guard
    assert all("com.acme.app" != h for h in hosts)               # mobile is NOT a host
    assert research.mobile_targets(acme) == ["com.acme.app"]
    # legal-by-construction: no attestation yet ⇒ stays dry-run/offline
    assert eng.attested() is False and eng.dry_run is True


def test_scaffold_saves_loadable_engagement():
    import tempfile
    acme = research.find(_progs(), "acme_cloud")
    p = os.path.join(tempfile.mkdtemp(), "engagement.json")
    research.scaffold(acme).save(p)
    from iolite.roe import Engagement
    eng = Engagement.load(p)
    assert eng.in_scope_hosts and eng.program.startswith("Acme")


def test_report_renders():
    txt = research.report(research.rank(_progs(), top=3))
    assert "IOLITE Research" in txt and "payout(" in txt
    assert "FOCUS" in txt and "--plan" in txt
