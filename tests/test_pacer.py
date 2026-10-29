"""
pacer — AIMD adaptive rate control with a virtual clock (deterministic, no real sleeping).
"""
from iolite.intent.pacer import AdaptivePacer


class VClock:
    def __init__(self): self.t = 0.0
    def now(self): return self.t
    def sleep(self, s): self.t += max(0.0, s)


def _p(rate=4.0):
    vc = VClock()
    return AdaptivePacer(rate=rate, clock=vc.now, sleep=vc.sleep), vc


def test_multiplicative_decrease_on_block():
    p, _ = _p(8.0)
    p.on_block()
    assert p.rate == 4.0
    p.on_block()
    assert p.rate == 2.0


def test_additive_increase_on_ok():
    p, _ = _p(2.0)
    before = p.rate
    p.on_ok()
    assert p.rate == before + p.ai


def test_rate_floor_and_ceiling():
    p, _ = _p(0.3)
    for _ in range(20):
        p.on_block()
    assert p.rate >= p.min_rate
    p2, _ = _p(24.0)
    for _ in range(50):
        p2.on_ok()
    assert p2.rate <= p2.max_rate


def test_retry_after_backoff_is_honored():
    p, vc = _p(10.0)
    p.on_block(retry_after=5.0)
    p.before()                       # must wait out the 5s backoff (virtual)
    assert vc.t >= 5.0


def test_before_paces_at_current_rate():
    p, vc = _p(2.0)                  # 2 req/s => 0.5s spacing
    p.before(); t1 = vc.t
    p.before(); t2 = vc.t
    assert (t2 - t1) >= 0.5 - 1e-9


def test_concurrency_grows_on_streak_and_shrinks_on_block():
    p, _ = _p(4.0)
    for _ in range(5):
        p.on_ok()
    assert p.concurrency >= 2
    p.on_block()
    assert p.concurrency >= 1
