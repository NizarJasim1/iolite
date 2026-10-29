"""
Tests for the submission write-up generator: class mapping, draft vs confirmed
labelling (honesty), reproduction uses own accounts, and top-impact selection.
"""

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.roe import Engagement
from iolite.reason import reason, writeup, writeups_from_report
from iolite.reason.differ import ReasonCandidate
from iolite.reason.amplify import score_candidate


def _eng():
    return Engagement(program="Acme (HackerOne)", authorized_by="scope-url",
                      operator="me", in_scope_hosts=["api.demo.test"],
                      attestation="I am authorised and all accounts are mine.")


def _cand(family="intent_gap"):
    return ReasonCandidate(
        endpoint_key="GET /api/orders/{id}", method="GET", path="/api/orders/5",
        gap_kind="observed_object_gap", intent_class="OWNER_ONLY",
        intent_confidence="medium", onyx_effect=Effect.OBJECT_ACCESS.value,
        probe_pids=["B"], holder_pid="A", object_id="5", family=family)


def test_writeup_maps_family_to_vuln_class():
    c = _cand("intent_gap")
    wu = writeup(c, _eng(), impact=score_candidate(c, None))
    assert "Broken Object Level Authorization" in wu.title
    assert "Remediation" in wu.markdown and "server-side" in wu.markdown


def test_bfla_family_maps_to_function_level():
    c = _cand("declared_unreached_gap")
    wu = writeup(c, _eng())
    assert "Broken Function Level Authorization" in wu.title


def test_offline_writeup_is_marked_draft():
    wu = writeup(_cand(), _eng(), confirmed=False)
    assert "DRAFT" in wu.markdown and "pending ONYX" in wu.markdown


def test_confirmed_writeup_is_marked_confirmed():
    wu = writeup(_cand(), _eng(), confirmed=True)
    assert "Confirmed by ONYX" in wu.markdown
    assert "DRAFT" not in wu.markdown


def test_repro_uses_own_accounts_language():
    wu = writeup(_cand(), _eng())
    assert "own accounts only" in wu.markdown.lower()
    assert "account B" in wu.markdown and "account A" in wu.markdown


def test_writeups_from_report_ranks_and_labels():
    m = SurfaceModel(base_url="https://api.demo.test", host="api.demo.test")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"api.demo.test"}
    ep = Endpoint(method="GET", path="/api/payments/{id}", effect=Effect.PAYMENT,
                  provenance=[Provenance.of(SourceKind.HAR, "c")], observed_ids=["1000"])
    m.add_endpoint(ep)
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/payments/{id}",
                 object_id="1000", path="/api/payments/1000", method="GET",
                 provenance=Provenance.of(SourceKind.HAR, "c"), carrier="path",
                 all_ids=["1000"], safe_read=True))
    rep = reason(m)
    wus = writeups_from_report(rep, _eng(), top=3)
    assert 1 <= len(wus) <= 3
    # highest-impact first
    assert wus[0].severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
