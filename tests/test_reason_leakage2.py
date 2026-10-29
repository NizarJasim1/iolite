"""
Tests for the closed gaps: feature-flag miner, mobile-strings + commits leakage, and
the coverage/recall meter.
"""

import os
import tempfile

from iolite.models import (Effect, Endpoint, ObservedAccess, Principal,
                           Provenance, SourceKind, SurfaceModel)
from iolite.reason import reason, mine_leakage, feature_flags, coverage
from iolite.reason.intent import AccessClass, infer_intent


def _prov():
    return Provenance.of(SourceKind.HAR, "cap")


def _write(d, name, text):
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


def test_feature_flags_extracts_privileged_names():
    js = "if (featureFlags.canDeleteUsers) { showAdminPanel(); } flags['enableBetaFoo']=1;"
    flags = feature_flags([js])
    assert "canDeleteUsers" in flags          # privileged (delete)
    assert "enableBetaFoo" not in flags        # not privileged → excluded


def test_feature_flag_raises_matching_endpoint_intent():
    m = SurfaceModel(host="h")
    m.add_endpoint(Endpoint(method="DELETE", path="/api/users/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    with tempfile.TemporaryDirectory() as d:
        js = _write(d, "app.js", "flags.canManageUsers = true;")
        lk = mine_leakage(m, js_paths=[js])
    # token 'users' shared between flag 'canManageUsers' and the endpoint path
    assert lk.get("DELETE /api/users/{id}") == AccessClass.ROLE_RESTRICTED


def test_mobile_strings_raise_admin_intent():
    m = SurfaceModel(host="h")
    m.add_endpoint(Endpoint(method="GET", path="/api/orders/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    with tempfile.TemporaryDirectory() as d:
        strings = _write(d, "app.strings", "https://h/api/admin/orders/list\n/api/orders/{id}\n")
        lk = mine_leakage(m, mobile_paths=[strings])
    assert lk.get("GET /api/orders/{id}") == AccessClass.ADMIN_ONLY  # 'orders' token, admin context


def test_commits_raise_intent():
    m = SurfaceModel(host="h")
    m.add_endpoint(Endpoint(method="GET", path="/api/invoices/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    with tempfile.TemporaryDirectory() as d:
        commits = _write(d, "git.log", "fix: add ownership/authz owner check on invoices endpoint")
        lk = mine_leakage(m, commits_paths=[commits])
    assert lk.get("GET /api/invoices/{id}") == AccessClass.OWNER_ONLY


def test_coverage_meter_counts_and_untested():
    m = SurfaceModel(base_url="https://h", host="h")
    m.principals = [Principal(pid="A", label="A", auth={"Authorization": "a"}),
                    Principal(pid="B", label="B", auth={"Authorization": "b"})]
    m.hosts_seen = {"h"}
    # one restricted endpoint WITH an observed access (coverable) …
    m.add_endpoint(Endpoint(method="GET", path="/api/orders/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()], observed_ids=["1"]))
    m.add_access(ObservedAccess(principal_id="A", endpoint_key="GET /api/orders/{id}",
                 object_id="1", path="/api/orders/1", method="GET", provenance=_prov(),
                 carrier="path", all_ids=["1"], safe_read=True))
    # … and one restricted endpoint with NO access and NO id source (untestable → untested)
    m.add_endpoint(Endpoint(method="POST", path="/api/admin/settings",
                            effect=Effect.AUTHORITY, provenance=[_prov()]))
    rep = reason(m)
    assert rep.coverage.restricted >= 1
    assert 0.0 <= rep.coverage.pct <= 1.0
    assert "coverage_pct" in rep.counts


def test_coverage_flags_crud_method_gaps():
    m = SurfaceModel(host="h")
    # only GET seen on an object resource → POST/PUT/PATCH/DELETE are gaps
    m.add_endpoint(Endpoint(method="GET", path="/api/things/{id}",
                            effect=Effect.OBJECT_ACCESS, provenance=[_prov()]))
    intent = infer_intent(m)
    cov = coverage(m, intent, [])
    assert any("/api/things/{id}" in g and "DELETE" in g for g in cov.method_gaps)
