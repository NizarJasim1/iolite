"""
IOLITE — command-line interface.

  python -m iolite demo                       # offline end-to-end on fixtures
  python -m iolite build --roe e.json --har A.har ... --out spec.json
  python -m iolite mine-js FILE...            # endpoints from JS / sourcemaps
  python -m iolite diff CURRENT ARCHIVED      # ghost-endpoint temporal diff
  python -m iolite triage spec.json           # show the authz-risk ranking
  python -m iolite roe-init [--out e.json]    # scaffold an engagement declaration

Passive-first and legal-by-construction: nothing here sends a packet. `build`
processes files you already captured; live acquisition/replay are opt-in extras.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .roe import Engagement
from .pipeline import Inputs, run
from . import js_extract, sourcemap, temporal_diff, onyx_spec

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FIXTURES = os.path.join(_PKG_ROOT, "fixtures")


def _cmd_roe_init(a):
    eng = Engagement.template()
    out = a.out or "engagement.json"
    eng.save(out)
    print(f"wrote engagement template → {out}")
    print("Edit it: set program, authorized_by, in_scope_hosts, and ATTEST before any "
          "live run. Placeholder values keep live/replay disabled (fail-safe).")


def _cmd_build(a):
    eng = Engagement.load(a.roe) if a.roe else Engagement.template()
    inputs = Inputs(
        har_files=a.har or [], js_files=a.js or [],
        sourcemap_files=a.sourcemap or [], archived_js_files=a.archived_js or [],
        graphql_file=a.graphql or "", openapi_file=a.openapi or "",
        base_url=a.base_url or "", max_probes=a.max_probes,
    )
    if getattr(a, "dir", None):                     # merge auto-detected folder inputs
        from . import detect
        det, roe_path, _notes = detect.detect_dir(a.dir)
        inputs.har_files += det.har_files
        inputs.js_files += det.js_files
        inputs.sourcemap_files += det.sourcemap_files
        inputs.archived_js_files += det.archived_js_files
        inputs.graphql_file = inputs.graphql_file or det.graphql_file
        inputs.openapi_file = inputs.openapi_file or det.openapi_file
        if roe_path and not a.roe:
            eng = Engagement.load(roe_path)
    if getattr(a, "runtime", None):
        inputs.runtime_files += list(a.runtime)
    res = run(eng, inputs, redact=not a.keep_tokens, deep=getattr(a, "deep", False))
    onyx_spec.write_spec(res.spec, a.out)
    print(f"\n✓ ONYX spec written → {a.out}")
    print(f"  endpoints={len(res.model.endpoints)}  "
          f"contract(probeable)={len(res.spec['contract'])}  "
          f"leads={len(res.spec['_iolite']['leads'])}  "
          f"principals={len(res.model.principals)}  "
          f"seed={len(res.plan.seed)}  probe={len(res.plan.probe)}  "
          f"ghosts={len(res.model.ghost_keys)}")
    if a.dossier:
        with open(a.dossier, "w", encoding="utf-8") as fh:
            fh.write(res.dossier)
        print(f"  dossier → {a.dossier}")
    if not eng.attested():
        print("  ⚠ engagement NOT attested — spec is for manual/offline use; "
              "live scanning stays gated until you attest in the ROE.")
    print("\nNext: python -m authpath scan " + a.out + " --out reports/")


def _cmd_demo(a):
    eng = Engagement(
        program="IOLITE self-demo (fixtures)",
        authorized_by="in-repo fixtures (self-authored, always authorised)",
        operator="demo", in_scope_hosts=["shop.demo.test"],
        automation_permitted=True, allow_destructive=False, dry_run=True,
        own_accounts_only=True,
        attestation="Fixtures are self-authored and safe to test.",
    )
    inputs = Inputs(
        har_files=[os.path.join(_FIXTURES, "capture_A.har"),
                   os.path.join(_FIXTURES, "capture_B.har")],
        js_files=[os.path.join(_FIXTURES, "app.current.js")],
        sourcemap_files=[os.path.join(_FIXTURES, "app.js.map")],
        archived_js_files=[os.path.join(_FIXTURES, "app.archived.js")],
        graphql_file=os.path.join(_FIXTURES, "graphql_introspection.json"),
    )
    res = run(eng, inputs, redact=True)
    out_spec = a.out or "demo_spec.json"
    out_dossier = a.dossier or "demo_surface.md"
    onyx_spec.write_spec(res.spec, out_spec)
    with open(out_dossier, "w", encoding="utf-8") as fh:
        fh.write(res.dossier)

    print("IOLITE self-demo — offline, deterministic\n")
    print(f"  principals (yours)  : {len(res.model.principals)}")
    print(f"  endpoints acquired  : {len(res.model.endpoints)}")
    print(f"  contract (probeable): {len(res.spec['contract'])}")
    print(f"  leads (need capture): {len(res.spec['_iolite']['leads'])}")
    print(f"  ghost endpoints     : {len(res.model.ghost_keys)}  ({res.ghost.summary})")
    print(f"  seed / probe items : {len(res.plan.seed)} / {len(res.plan.probe)}")
    print("\n  top authz-risk candidates:")
    for ep in res.model.sorted_endpoints()[:8]:
        if ep.risk <= 0:
            continue
        print(f"    [{ep.risk:>3}] {ep.key:<42} {ep.effect.value}")
    print(f"\n  → {out_spec}  (feed to ONYX)   → {out_dossier}  (human dossier)")


def _cmd_mine_js(a):
    total = {}
    for path in a.files:
        text = open(path, "r", encoding="utf-8", errors="replace").read()
        if path.endswith(".map"):
            eps, sources, flags = sourcemap.parse_sourcemap(text, path)
            print(f"\n{path}: {len(eps)} endpoint(s), {len(sources)} source file(s)")
        else:
            eps = js_extract.extract_endpoints(text, path)
            print(f"\n{path}: {len(eps)} endpoint(s)")
        for ep in eps:
            total[ep.key] = ep
    print(f"\n= {len(total)} unique endpoint(s) mined:")
    for key in sorted(total):
        ep = total[key]
        tag = f"  [{','.join(ep.role_hints)}]" if ep.role_hints else ""
        print(f"  {ep.effect.value:<15} {key}{tag}")


def _cmd_diff(a):
    cur = [(open(a.current, encoding="utf-8", errors="replace").read(), a.current)]
    arch = [(open(a.archived, encoding="utf-8", errors="replace").read(), a.archived)]
    rep = temporal_diff.diff(cur, arch)
    print(rep.summary)
    for ep in rep.ghosts:
        print(f"  ghost: {ep.key}  ({ep.effect.value})")


def _cmd_serve(a):
    from .serve import serve
    serve(a.host, a.port, open_browser=not a.no_open)


def _cmd_go(a):
    """One command: detect a folder's captures, build, verify with ONYX."""
    from . import detect, onyx_link
    inputs, roe_path, notes = detect.detect_dir(a.dir)
    print(f"detected: {detect.summarize(inputs)}")
    for n in notes[:6]:
        print(f"  · {n}")
    if roe_path:
        eng = Engagement.load(roe_path)
        print(f"engagement: {roe_path}  (attested: {eng.attested()})")
    else:
        eng = Engagement.template()
        if a.scope:
            eng.in_scope_hosts = a.scope.split(",")
            eng.attestation = "operator-provided scope via --scope"
        print("⚠ no engagement file found — using a template; set --scope or add roe.json "
              "and ATTEST before any live use")
    res = run(eng, inputs, redact=not a.keep_tokens)
    out = a.out or os.path.join(a.dir, "iolite_spec.json")
    onyx_spec.write_spec(res.spec, out)
    print(f"\n✓ spec → {out}")
    print(f"  contract(probeable)={len(res.spec['contract'])}  "
          f"leads={len(res.spec['_iolite']['leads'])}  "
          f"probes={len(res.plan.probe)}  principals={len(res.model.principals)}")
    v = onyx_link.verify_spec(res.spec)
    if v.get("available") and v.get("parses"):
        if v.get("agree"):
            print(f"✓ ONYX agrees — {v['requests']} requests all map to "
                  f"{v['contract_endpoints']} contract endpoints ({', '.join(v['principals'])})")
        else:
            print(f"⚠ ONYX recognised {v.get('recognised')}/{v.get('requests')} requests; "
                  f"unrecognised: {v.get('unrecognised')}")
    elif v.get("available"):
        print(f"⚠ ONYX could not parse the spec: {v.get('error')}")
    else:
        print("· ONYX not linked (set ONYX_PATH to auto-verify and scan)")
    print(f"\nNext: python -m authpath scan {out} --out reports/")


def _cmd_reason(a):
    """reason: reconstruct developer INTENT, measure ENFORCEMENT, hunt I△E +
    transplanted-invariant violations + negated assumptions → ONYX-ready candidates.
    Additive 'brain' over the acquired surface — proposes; ONYX disposes (QL5)."""
    from . import detect, onyx_link
    from .reason import (reason as run_reason, build_reason_spec, render_report,
                         run_acquisition)
    inputs, roe_path, notes = detect.detect_dir(a.dir)
    rt = list(getattr(a, "runtime", None) or [])
    if rt:
        inputs.runtime_files = (getattr(inputs, "runtime_files", None) or []) + rt
    print(f"detected: {detect.summarize(inputs)}")
    for n in notes[:4]:
        print(f"  · {n}")
    if roe_path:
        eng = Engagement.load(roe_path)
        print(f"engagement: {roe_path}  (attested: {eng.attested()})")
    else:
        eng = Engagement.template()
        if a.scope:
            eng.in_scope_hosts = a.scope.split(",")
            eng.attestation = "operator-provided scope via --scope"
        print("⚠ no engagement file — using a template; set --scope or add roe.json "
              "and ATTEST before any live use")
    res = run(eng, inputs, redact=not a.keep_tokens, deep=getattr(a, "deep", False))
    archived_urls = None
    if getattr(a, "archived_urls", None):
        try:
            with open(a.archived_urls, "r", encoding="utf-8", errors="replace") as fh:
                archived_urls = [ln.strip() for ln in fh if ln.strip()]
        except OSError as e:
            print(f"  · --archived-urls unreadable, skipped: {e}")
    rep = run_reason(res.model, inputs,
                     mobile_paths=getattr(a, "mobile", None) or [],
                     commits_paths=getattr(a, "commits", None) or [],
                     with_workflow=getattr(a, "sequence", False),
                     rich_intent=getattr(a, "rich_intent", False),
                     with_acquisition=getattr(a, "acquire", False),
                     archived_urls=archived_urls, engagement=eng)
    spec = build_reason_spec(res.model, rep, eng,
                             max_probes=a.max_probes, redact=not a.keep_tokens)
    out = a.out or os.path.join(a.dir, "iolite_reason_spec.json")
    onyx_spec.write_spec(spec, out)
    print(f"\n✓ reason spec → {out}")
    print(f"  intent-restricted={rep.counts['intent_restricted']}  "
          f"candidates={rep.counts['candidates']}  families={rep.by_family()}")
    if rep.counts.get("workflow_guards"):
        print(f"  workflow guards (declared): {rep.counts['workflow_guards']} "
              f"→ state-indexed gate-skip/transition hypotheses")
    if rep.quickwins:
        qsev = {}
        for q in rep.quickwins:
            qsev[q.severity] = qsev.get(q.severity, 0) + 1
        print(f"  quick-wins (passive, payable): {len(rep.quickwins)}  {qsev}")
    if rep.acquisition is not None:
        acq = rep.acquisition
        if acq.architecture:
            print(f"  architecture: {acq.architecture.get('topology','?')} / "
                  f"{acq.architecture.get('authz_pattern','?')}  "
                  f"pressure-points={len(acq.architecture.get('pressure_points', []))}")
        if acq.federation.get("present"):
            print(f"  identity surface: {acq.federation.get('provider') or 'IdP'} / "
                  f"{acq.federation.get('protocol') or '?'}  "
                  f"leads={len(acq.federation.get('leads', []))}")
        if acq.mobile.get("mobile_only"):
            print(f"  mobile-only surface: {len(acq.mobile['mobile_only'])} endpoint(s); "
                  f"staging hosts={len(acq.mobile.get('hosts_staging', []))}")
        if acq.ghosts:
            top = acq.ghosts[0]
            print(f"  ghosts (archived, authz-ranked): {len(acq.ghosts)}  "
                  f"top=[{top['score']}] {top['key']}")
        print(f"  acquisition: hidden-leads={len(acq.hidden_leads)} "
              f"existence-hits={len(acq.existence_hits)} "
              f"capture-steps={len(acq.capture_plan)} feedback-applied={acq.feedback_applied}")
        for n in acq.notes[:3]:
            print(f"    · {n}")

    confirmed_keys = set()
    if getattr(a, "cegar", False):
        from .reason import refine_search, StaticOracle, LiveOnyxOracle
        live = eng.attested() and onyx_link.available()
        oracle = LiveOnyxOracle() if live else StaticOracle()
        trace = refine_search(res.model, eng, oracle=oracle, depth=a.depth, inputs=inputs)
        confirmed_keys = {s["cand"] for s in trace.confirmed_chain}
        print(f"\n{trace.summary()}")
        if oracle.kind != "live":
            print("  · offline oracle: candidates stay UNKNOWN — the loop closes only "
                  "on a LIVE attested target (restore tokens + attest, run on your machine).")
        for step in trace.confirmed_chain[:12]:
            print(f"  ✓ depth {step['depth']} [{step['effect']}] {step['endpoint']} "
                  f"obj={step['object'] or '-'}"
                  + (f"  ⇐ {step['from']}" if step['from'] else ""))
        spec["_reason"]["cegar"] = {
            "oracle": trace.oracle_kind, "depth_k": trace.depth_k,
            "rounds": [{"depth": r.depth, "tested": r.tested,
                        "confirmed": len(r.confirmed), "denied": r.denied,
                        "unknown": r.unknown, "spawned": r.spawned} for r in trace.rounds],
            "confirmed_chain": trace.confirmed_chain, "pruned": trace.pruned}
        # close the loop: a CONFIRMED finding re-weights acquisition discovery/capture
        # toward its neighbourhood for the next pass (feedback.py). Opt-in with --acquire.
        if getattr(a, "acquire", False) and trace.confirmed_chain:
            findings = [{"family": s.get("effect", ""), "path": s.get("endpoint", ""),
                         "object_type": s.get("object", ""), "method": "GET"}
                        for s in trace.confirmed_chain]
            rep.acquisition = run_acquisition(
                res.model, inputs, mobile_paths=getattr(a, "mobile", None) or [],
                archived_urls=archived_urls, engagement=eng, confirmed_findings=findings)
            spec["_reason"]["acquisition"] = rep.acquisition.summary()
            print(f"  ↻ feedback: re-weighted {rep.acquisition.feedback_applied} "
                  f"discovery candidate(s) toward {len(findings)} confirmed finding(s)")
        onyx_spec.write_spec(spec, out)
    # Cross-session KB (regression/fresh signals) + EV submission gate
    kb_sig = None
    if getattr(a, "kb", None):
        from .reason import load_kb, save_kb, kb_signals, kb_update
        prog = eng.program or os.path.basename(os.path.abspath(a.dir))
        kbobj = load_kb(a.kb)
        prior = kbobj.program(prog)
        kb_sig = kb_signals(prior, rep.intent, rep.guards)
        kb_update(kbobj, prog, rep.intent, rep.guards)
        save_kb(a.kb, kbobj)
        if kb_sig["regressions"]:
            print(f"  ⚠ KB: {len(kb_sig['regressions'])} guard REGRESSION(s) since last "
                  f"session — freshly-introduced bug(s), very low collision!")
        if kb_sig["fresh"]:
            print(f"  KB: {len(kb_sig['fresh'])} fresh endpoint(s) unseen in a prior session")
    if getattr(a, "readiness", False) or kb_sig is not None:
        from .reason import assess_readiness_report, readiness_summary
        readies = assess_readiness_report(rep, confirmed_keys=confirmed_keys, kb_sig=kb_sig)
        print(f"  readiness (EV gate): {readiness_summary(readies)}  "
              f"{'(offline ⇒ HOLD/DROP until ONYX confirms live)' if not confirmed_keys else ''}")
        spec["_reason"]["readiness"] = [
            {"cand": r.cand_key, "verdict": r.verdict, "ev": r.ev,
             "e_payout": r.e_payout, "factors": r.factors} for r in readies[:20]]
        onyx_spec.write_spec(spec, out)

    if a.dossier:
        with open(a.dossier, "w", encoding="utf-8") as fh:
            fh.write(render_report(rep))
        print(f"  reason dossier → {a.dossier}")
    v = onyx_link.verify_spec(spec)
    if v.get("available") and v.get("parses"):
        print(f"✓ ONYX parses — {v.get('recognised')}/{v.get('requests')} "
              f"requests map to {v.get('contract_endpoints')} contract endpoints")
    elif v.get("available"):
        print(f"⚠ ONYX could not parse: {v.get('error')}")
    else:
        print("· ONYX not linked (set ONYX_PATH to auto-verify and scan)")
    if getattr(a, "writeup", None):
        from .reason import writeups_from_report, quickwin_writeup
        os.makedirs(a.writeup, exist_ok=True)
        wus = writeups_from_report(rep, eng, confirmed_keys=confirmed_keys, top=a.writeup_top)
        for i, wu in enumerate(wus, 1):
            fn = os.path.join(a.writeup, f"finding_{i:02d}_{wu.severity.lower()}.md")
            with open(fn, "w", encoding="utf-8") as fh:
                fh.write(wu.markdown)
        qn = 0
        for q in rep.quickwins:
            qw = quickwin_writeup(q, eng)
            qn += 1
            fn = os.path.join(a.writeup, f"quickwin_{qn:02d}_{qw.severity.lower()}.md")
            with open(fn, "w", encoding="utf-8") as fh:
                fh.write(qw.markdown)
        conf = len(confirmed_keys)
        print(f"\n✓ {len(wus)} authz write-up(s) ({conf} ONYX-confirmed, "
              f"{len(wus)-min(conf,len(wus))} draft) + {qn} quick-win report(s) → {a.writeup}/")

    if not eng.attested():
        print("  ⚠ engagement NOT attested — offline/manual only; live scan gated "
              "until you attest in the ROE (fail-safe).")
    print(f"\nNext: python -m authpath scan {out} --out reports/")


def _cmd_research(a):
    from . import research
    if a.watch:
        old = research.load_file(a.watch[0])
        new = research.load_file(a.watch[1])
        fresh = research.diff_new(old, new)
        print(f"{len(fresh)} NEW program(s) since the previous dump:\n")
        print(research.report(fresh[:a.top] if a.top else fresh))
        return 0

    progs = []
    if a.live:
        for pl in (a.platforms or "hackerone,bugcrowd").split(","):
            pl = pl.strip()
            try:
                progs += research.fetch_live(pl)
                print(f"  fetched {pl}")
            except Exception as e:
                print(f"  live {pl}: {type(e).__name__}: {e}")
    for f in (a.source or []):
        progs += research.load_file(f)
    if not progs:
        print("no data. Use --live, or --source FILE (download the ~30-min-fresh dumps from\n"
              f"  {research.RAW_BASE}/hackerone_data.json  etc.)")
        return 1

    # focus one program: surface plan or engagement scaffold
    if a.plan or a.scaffold:
        h = a.plan or a.scaffold
        p = research.find(progs, h)
        if not p:
            print(f"program '{h}' not found in the loaded data (use its handle).")
            return 1
        research.score(p)                       # so the plan header shows real tier/score
        if a.plan:
            print(research.plan(p))
            return 0
        eng = research.scaffold(p)
        out = a.out or "engagement.json"
        eng.save(out)
        print(f"wrote engagement scaffold → {out}   (program: {eng.program})")
        print(f"  in-scope hosts seeded from public scope: {eng.in_scope_hosts or '(none — mobile-only?)'}")
        mob = research.mobile_targets(p)
        if mob:
            print(f"  mobile targets (capture app traffic, not a host): {mob}")
        print("  NEXT: open it, set operator + out_of_scope_hosts, and WRITE an attestation")
        print("        (it stays dry-run/offline until you attest — legal-by-construction).")
        print(f"  then: iolite go --dir ./captures --roe {out}")
        return 0

    # persistent uncrowded ledger: bonus for programs unseen before, then record
    fresh_keys = frozenset()
    if a.ledger:
        seen = research.load_ledger(a.ledger)
        if seen:                                    # first run only seeds — no false edge
            fresh_keys = frozenset(p.key for p in progs if p.key not in seen)
            print(f"  ledger: {len(fresh_keys)} program(s) unseen before → 🌱 uncrowded bonus")
        else:
            print(f"  ledger: seeding {a.ledger} (first run — no bonus yet)")

    top = research.rank(progs, top=a.top, paid_only=not a.include_vdp, fresh_keys=fresh_keys)
    print(research.report(top))
    if a.ledger:
        research.save_ledger(a.ledger, progs)
    return 0


def _cmd_live(a):
    """Fail-CLOSED live gateway. Runs the offline build + preflight and shows
    the human-gated next steps. Sends NO packets itself; live confirmation stays a
    deliberate, ONYX-verified, human-initiated step."""
    from . import detect
    from .preflight import preflight
    inputs, roe_path, notes = detect.detect_dir(a.dir)
    if roe_path:
        eng = Engagement.load(roe_path)
    else:
        eng = Engagement.template()
        if a.scope:
            eng.in_scope_hosts = a.scope.split(",")
            eng.attestation = "operator-provided scope via --scope"
    if getattr(a, "samples", None):
        from .live_calibrate import calibrate_from_samples
        try:
            data = json.load(open(a.samples, encoding="utf-8"))
            samples = data if isinstance(data, list) else data.get("samples", [])
            prof = calibrate_from_samples(samples)
            print(f"STABILITY CALIBRATION ({prof.samples} sample(s)): "
                  f"volatile={len(prof.volatile_fields)}  noise={prof.noise_ratio}  "
                  f"stability_k={prof.stability_k}")
            for n in prof.notes:
                print(f"  · {n}")
            print(f"  → set on ONYX before the live scan: {prof.to_onyx()}\n")
        except Exception as e:      # noqa: BLE001
            print(f"(calibration skipped: {type(e).__name__}: {e})\n")

    res = run(eng, inputs, redact=not a.keep_tokens, deep=getattr(a, "deep", False))
    rep = preflight(eng, res.model, res.spec, allow_write=getattr(a, "allow_write", False))
    print("PREFLIGHT — fail-closed, no packets sent:\n")
    print(rep.render())

    print("\nNEXT (every step is human-gated; nothing fires until you run it):")
    if not rep.go:
        print("  ✗ NO-GO — fix the red gate(s) above. No live step proceeds until GREEN.")
        return 1
    print("  1) Capture as EACH of your accounts (paste assets/iolite_surface_hook.js in DevTools).")
    print("  2) Calibrate non-determinism: read your OWN object ~5× → samples.json →")
    print("       iolite live --dir <dir> --samples samples.json   (protects zero-FP)")
    print("  3) Reason offline:  iolite reason --dir <dir> --sequence --deep --rich-intent --readiness")
    print("  4) LIVE confirm (only when live-ready + attested):")
    print("       ONYX_PATH=/path/to/onyx iolite reason --dir <dir> --cegar --depth 3 "
          "--keep-tokens --writeup findings/")
    print("  5) Submit ONLY 'GO' findings; then record the outcome:")
    print("       iolite econ --file econ.json --add --program <p> --status paid --payout N --hours H")
    print(f"\n  live-ready (mandatory gates + ONYX linked): {rep.live_ready}")
    return 0


def _cmd_econ(a):
    """Measured operating ledger → realized $/hour + FOCUS/ROTATE/DROP (goals 2 & 5)."""
    from .reason import (load_ledger, save_ledger, EconEntry, portfolio_summary)
    entries = load_ledger(a.file)
    if a.add:
        entries.append(EconEntry(program=a.program or "?", status=a.status or "pending",
                                 payout=a.payout or 0.0, hours=a.hours or 0.0,
                                 finding=a.finding or "", date=a.date or ""))
        save_ledger(a.file, entries)
        print(f"✓ recorded → {a.file}  ({len(entries)} entries)")
    if not entries:
        print("no ledger entries yet. Record one:\n"
              "  iolite econ --file econ.json --add --program inDrive --status paid "
              "--payout 1500 --hours 6")
        return 0
    s = portfolio_summary(entries)
    print(f"\nportfolio: {s['submissions']} submissions · {s['paid']} paid · "
          f"${s['dollars']} over {s['hours']}h · blended ${s['blended_dollars_per_hour']}/hr\n")
    print("per-program recommendation (realized, not predicted):")
    for r in s["recommendations"]:
        print(f"  [{r['action']:<7}] {r['program']:<26} ${r['dollars_per_hour']}/hr "
              f" acc={r['acceptance_rate']}  — {r['reason']}")
    return 0


def _cmd_verify(a):
    from . import onyx_link
    spec = json.load(open(a.spec, encoding="utf-8"))
    v = onyx_link.verify_spec(spec)
    if not v.get("available"):
        print("ONYX not linked:", v.get("hint") or v.get("error"))
        return 1
    if not v.get("parses"):
        print("ONYX could NOT parse the spec:", v.get("error"))
        return 1
    print("✓ ONYX parses this spec")
    print(f"  principals        : {', '.join(v['principals'])}")
    print(f"  contract endpoints: {v['contract_endpoints']}")
    print(f"  requests recognised: {v['recognised']}/{v['requests']}")
    if v["unrecognised"]:
        print(f"  ⚠ unrecognised    : {v['unrecognised']}")
    print("  agreement         :", "FULL" if v["agree"] else "PARTIAL")
    return 0


def _cmd_selftest(a):
    from .calibrate import calibrate, BUNDLE_TRUTH
    path = a.bundle or os.path.join(_FIXTURES, "calibration_bundle.js")
    with open(path, encoding="utf-8") as fh:
        cal = calibrate(fh.read(), BUNDLE_TRUTH)
    print("IOLITE extraction calibration\n")
    print(cal.report())
    ok = cal.recall >= 0.9 and cal.clean
    print("\n" + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _cmd_triage(a):
    spec = json.load(open(a.spec, encoding="utf-8"))
    cands = (spec.get("_iolite") or {}).get("top_candidates") or []
    if not cands:
        print("no _iolite.top_candidates in spec (was it produced by IOLITE?)")
        return
    print(f"authz-risk ranking ({len(cands)} candidates):\n")
    for i, c in enumerate(cands, 1):
        print(f"{i:>2}. [{c['risk']:>3}] {c['endpoint']}  ({c['effect']})")
        for r in c.get("reasons", []):
            print(f"       {r}")


def _cmd_hunt(a):
    """FIELD driver: real multi-account captures -> offline-proven bugs (0 requests) +
    EV-ranked divergence leads + a submittable dossier; optional gated live confirm."""
    import json as _json
    from .intent.hunt import hunt
    from .intent import dossier
    eng = None
    if a.roe:
        eng = Engagement.load(a.roe)
        print(f"engagement: {a.roe} (attested: {eng.attested()})")
    elif a.scope:
        eng = Engagement.template()
        eng.program = a.authorized_by or "authorized target"
        eng.in_scope_hosts = a.scope.split(",")
        eng.authorized_by = a.authorized_by or ""
        eng.attestation = a.authorized_by or ""   # attested only if a real basis is given
        print(f"⚠ no roe file — scope from --scope ({eng.in_scope_hosts}); "
              f"attested={eng.attested()}")
    else:
        print("⚠ no --roe and no --scope: ingesting all hosts in the captures (offline only).")
    target_cfg = None
    if a.target:
        with open(a.target, encoding="utf-8") as fh:
            target_cfg = _json.load(fh)
    principal_auth = None
    if getattr(a, "principals_file", None):
        with open(a.principals_file, encoding="utf-8") as fh:
            principal_auth = _json.load(fh)   # {"pid": {"authorization": "Bearer …"}, …}
    rep = hunt(a.dir, engagement=eng, budget=a.max_probes, live=a.live, target_cfg=target_cfg,
               live_replay=getattr(a, "replay", False), principal_auth=principal_auth,
               base_url=getattr(a, "base_url", "") or "")
    print(f"principals={rep.principals}  exchanges={rep.exchanges}  "
          f"CORROBORATED(offline,0 req)={len(rep.corroborated)}  leads={len(rep.leads)}")
    print(f"families={rep.by_family}")
    if a.live or getattr(a, "replay", False):
        print(f"live: {rep.live_status}  (intervention={len(rep.live_findings)}, "
              f"replay-confirmed={len(rep.confirm_findings)})")
    md = dossier.render(rep, program=(eng.program if eng else ""))
    out = a.out or os.path.join(a.dir, "iolite_dossier.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"✓ dossier → {out}")
    return 0


def _cmd_gen_target(a):
    """Auto-derive an engine intervention target.json from captures. REVIEW _TODO before any
    live, write-capable run — this is a proposal, not an authorization."""
    import json as _json
    from .intent.har_capture import exchanges_from_dir
    from .intent.target_gen import generate_target, to_json
    scope = set(h.strip() for h in (a.scope or "").split(",") if h.strip()) or None
    pa = None
    if a.principals_file:
        with open(a.principals_file, encoding="utf-8") as fh:
            pa = _json.load(fh)
    ex = exchanges_from_dir(a.dir, scope_hosts=scope)
    cfg = generate_target(ex, principal_auth=pa, base_url=a.base_url or "")
    out = a.out or "target.json"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(to_json(cfg))
    print(f"✓ target.json → {out}  ({len(cfg['kinds'])} kind(s) derived)")
    print("  REVIEW before any live write-capable run:")
    for t in cfg.get("_TODO", []):
        print("   · " + t)
    print("  then:  python3 -m iolite.intent " + out + "   (gated engine; writes dry-run until attested)")
    return 0


def _cmd_watch(a):
    """LIVE: scan passively WHILE you browse. Starts a loopback collector, prints a
    per-account hook snippet, and prints cross-account confirmations the instant they
    appear. Sends nothing itself; in-scope hosts only. Writes a dossier on stop."""
    import time as _t
    from .intent.live_session import LiveSession
    from .intent.collector import Collector
    from .intent import dossier
    scope = set(h.strip() for h in (a.scope or "").split(",") if h.strip())
    eng = Engagement.load(a.roe) if a.roe else None
    if eng and not scope:
        scope = set(eng.in_scope_hosts)
    if not scope:
        print("⚠ no --scope/--roe: EVERY host in your session will be ingested. Prefer --scope.")
    sess = LiveSession(scope_hosts=scope or None, engagement=eng)

    def _alert(ev):
        tag = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]"}.get(ev.severity, "[ •  ]")
        print(f"  {tag} {ev.title}" + (f"  — {ev.detail}" if ev.detail else ""))

    col = Collector(sess, host=a.host, port=a.port, on_event=_alert).start()
    print(f"IOLITE watch live on http://{a.host}:{a.port}  |  scope={sorted(scope) or '(ALL — unsafe)'}")
    print(f"→ LIVE DASHBOARD: http://{a.host}:{a.port}/   (relation graph · learned policy · confirmations)")
    print("Paste ONE snippet in EACH account's DevTools console (label must match the account):")
    for lbl in (a.principals or "A,B").split(","):
        print(f"\n  // account {lbl.strip()}:\n  {col.snippet(lbl.strip())}")
    print("\nNow browse normally with each account. Live confirmations appear below.")
    print("Ctrl-C to stop and write the dossier.\n")
    try:
        if a.duration:
            _t.sleep(a.duration)
        else:
            while True:
                _t.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        col.stop()
    out = a.out or "iolite_live_dossier.md"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(dossier.render(sess.snapshot(), program=(eng.program if eng else "")))
    st = sess.status()
    pol = sess.policy().get("object_types", {})
    enforced = [t for t, p in pol.items() if p.get("enforced")]
    print(f"\n✓ stopped. exchanges={st['exchanges']} corroborated(0-request)={st['corroborated']} "
          f"learned-types={st['learned_types']} enforced-boundaries={enforced} → dossier {out}")
    return 0


def _cmd_sim(a):
    """Internal, fully-synthetic readiness simulation against hardened-target models."""
    from .intent import simlab
    results = simlab.run_all(seed=a.seed)
    report = simlab.build_report(results)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(report)
        ok, bola, ten, clean = simlab._verdict(results)
        print(f"✓ wrote {a.out} — operational {ok}/{len(results)}, BOLA {bola}/{len(results)}, "
              f"cross-tenant {ten}/{len(results)}, clean={clean}")
    else:
        print(report)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="iolite",
                                 description="Legal deep authz-surface acquisition — feeds ONYX")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="offline end-to-end on bundled fixtures")
    d.add_argument("--out", help="spec output path (default demo_spec.json)")
    d.add_argument("--dossier", help="dossier output path (default demo_surface.md)")
    d.set_defaults(fn=_cmd_demo)

    b = sub.add_parser("build", help="run the pipeline on your captured inputs")
    b.add_argument("--dir", help="auto-detect and include all captures under this folder")
    b.add_argument("--roe", help="engagement (rules-of-engagement) JSON")
    b.add_argument("--har", action="append", help="authenticated HAR (repeatable, one per account)")
    b.add_argument("--js", action="append", help="current JS bundle (repeatable)")
    b.add_argument("--sourcemap", action="append", help=".js.map sourcemap (repeatable)")
    b.add_argument("--archived-js", action="append", help="archived JS bundle (repeatable)")
    b.add_argument("--graphql", help="GraphQL introspection JSON")
    b.add_argument("--openapi", help="OpenAPI/Swagger JSON")
    b.add_argument("--base-url", help="override base_url")
    b.add_argument("--max-probes", type=int, default=500)
    b.add_argument("--keep-tokens", action="store_true",
                   help="do NOT redact live credentials (unsafe)")
    b.add_argument("--out", default="spec.json", help="ONYX spec output path")
    b.add_argument("--dossier", help="also write a human surface dossier here")
    b.add_argument("--deep", action="store_true",
                   help="deep surface recovery (client GraphQL, config "
                        "endpoints, runtime self-disclosure) — passive, obfuscation-resistant")
    b.add_argument("--runtime", action="append",
                   help="runtime self-disclosure log(s) from the in-page hook")
    b.set_defaults(fn=_cmd_build)

    m = sub.add_parser("mine-js", help="extract endpoints from JS / sourcemaps")
    m.add_argument("files", nargs="+")
    m.set_defaults(fn=_cmd_mine_js)

    df = sub.add_parser("diff", help="ghost-endpoint temporal diff")
    df.add_argument("current"); df.add_argument("archived")
    df.set_defaults(fn=_cmd_diff)

    t = sub.add_parser("triage", help="show the authz-risk ranking from a IOLITE spec")
    t.add_argument("spec")
    t.set_defaults(fn=_cmd_triage)

    go = sub.add_parser("go", help="ONE command: detect a folder's captures → build → verify with ONYX")
    go.add_argument("--dir", required=True, help="folder containing your captures (HAR/JS/maps/…)")
    go.add_argument("--scope", help="comma-separated in-scope hosts (if no roe/engagement.json present)")
    go.add_argument("--out", help="spec output path (default <dir>/iolite_spec.json)")
    go.add_argument("--keep-tokens", action="store_true", help="do NOT redact credentials")
    go.set_defaults(fn=_cmd_go)

    rn = sub.add_parser("reason", help="grey-box authz brain: reconstruct intent, "
                        "hunt I△E + invariants + assumptions → ONYX candidates")
    rn.add_argument("--dir", required=True, help="folder with your captures (HAR/JS/maps/GraphQL/OpenAPI)")
    rn.add_argument("--scope", help="comma-separated in-scope hosts (if no roe/engagement.json present)")
    rn.add_argument("--out", help="reason spec output path (default <dir>/iolite_reason_spec.json)")
    rn.add_argument("--dossier", help="also write a human reason dossier here")
    rn.add_argument("--max-probes", type=int, default=500)
    rn.add_argument("--keep-tokens", action="store_true", help="do NOT redact credentials")
    rn.add_argument("--cegar", action="store_true",
                    help="run the CEGAR loop (ONYX oracle in-search; live only under attestation)")
    rn.add_argument("--depth", type=int, default=3, help="CEGAR bounded search depth k")
    rn.add_argument("--mobile", action="append",
                    help="your own app's extracted strings (strings/jadx/smali/plist) — intent leakage")
    rn.add_argument("--commits", action="append",
                    help="a public commit log/diff dump — intent leakage")
    rn.add_argument("--writeup", metavar="DIR",
                    help="write submission-ready BOLA/BFLA report(s) to this folder")
    rn.add_argument("--writeup-top", type=int, default=5,
                    help="how many top-impact findings to write up (default 5)")
    rn.add_argument("--sequence", action="store_true",
                    help="mine DECLARED workflow guards → state-indexed "
                         "gate-skip / privileged-transition hypotheses (ONYX confirms)")
    rn.add_argument("--rich-intent", action="store_true",
                    help="IntentGraph — multi-principal partition + learned "
                         "vocabulary + monotone propagation (raises recall, never lowers)")
    rn.add_argument("--readiness", action="store_true",
                    help="expected-value submission gate (GO/HOLD/DROP) per finding")
    rn.add_argument("--kb", metavar="PATH",
                    help="cross-session knowledge base — detects guard "
                         "regressions (fresh bugs) + fresh endpoints, then updates itself")
    rn.add_argument("--deep", action="store_true",
                    help="deep surface recovery (client GraphQL ops, route "
                         "tables, runtime-observed calls) — obfuscation-resistant, passive")
    rn.add_argument("--runtime", action="append",
                    help="runtime self-disclosure log(s) from the passive in-page hook "
                         "(assets/iolite_surface_hook.js) — highest-tier surface")
    rn.add_argument("--acquire", action="store_true",
                    help="acquisition chain: model the target's authz architecture + "
                         "identity surface, rank archived ghosts, mine the mobile-only "
                         "surface, propose hidden paths (existence confirmed under ROE), "
                         "and emit a coverage-guided capture plan; with --cegar/--kb a "
                         "confirmed finding re-weights discovery toward its neighbourhood")
    rn.add_argument("--archived-urls", metavar="FILE",
                    help="a Wayback/gau URL feed (one per line) → authz-ranked ghosts")
    rn.set_defaults(fn=_cmd_reason)

    vf = sub.add_parser("verify", help="check a spec through ONYX's own loaders (offline)")
    vf.add_argument("spec")
    vf.set_defaults(fn=_cmd_verify)

    lv = sub.add_parser("live", help="fail-closed live gateway — preflight + "
                        "non-determinism calibration + human-gated next steps (no packets)")
    lv.add_argument("--dir", required=True, help="folder with your captures + engagement/roe.json")
    lv.add_argument("--scope", help="comma-separated in-scope hosts (if no roe present)")
    lv.add_argument("--deep", action="store_true", help="include Point-2 deep acquisition in the build")
    lv.add_argument("--keep-tokens", action="store_true", help="do NOT redact credentials")
    lv.add_argument("--allow-write", action="store_true",
                    help="declare intent for ONE bounded reversible-preferred write on your "
                         "OWN object (still requires allow_destructive + attestation)")
    lv.add_argument("--samples", metavar="JSON",
                    help="repeated reads of your OWN object → calibrate the target's "
                         "non-determinism baseline (protects ONYX zero-false-positive)")
    lv.set_defaults(fn=_cmd_live)

    ec = sub.add_parser("econ", help="measured $/hour ledger → FOCUS/ROTATE/DROP")
    ec.add_argument("--file", default="econ.json", help="ledger JSON path")
    ec.add_argument("--add", action="store_true", help="append an entry, then show the summary")
    ec.add_argument("--program", help="program handle/name")
    ec.add_argument("--status", help="paid|duplicate|informational|not-applicable|out-of-scope|pending")
    ec.add_argument("--payout", type=float, help="USD (or crypto-equivalent) received")
    ec.add_argument("--hours", type=float, help="hours spent on this submission")
    ec.add_argument("--finding", help="short label / cand_key")
    ec.add_argument("--date", help="optional ISO date")
    ec.set_defaults(fn=_cmd_econ)

    rs = sub.add_parser("research", help="rank live bug-bounty programs by fit for your toolchain (public data)")
    rs.add_argument("--source", action="append", help="bounty-targets-data JSON file (repeatable)")
    rs.add_argument("--live", action="store_true", help="fetch latest ~30-min dumps from GitHub (needs network)")
    rs.add_argument("--platforms", help="comma list for --live (default: hackerone,bugcrowd)")
    rs.add_argument("--top", type=int, default=5)
    rs.add_argument("--include-vdp", action="store_true", help="include non-paying VDPs")
    rs.add_argument("--watch", nargs=2, metavar=("OLD", "NEW"), help="diff two dumps → brand-new programs")
    rs.add_argument("--ledger", help="persistent uncrowded ledger file: programs unseen before "
                                     "get a 🌱 uncrowded bonus, then are recorded")
    rs.add_argument("--plan", metavar="HANDLE", help="print the IOLITE→ONYX surface map for one program")
    rs.add_argument("--scaffold", metavar="HANDLE", help="write a ready-to-run engagement (RoE) for one program")
    rs.add_argument("--out", help="output path for --scaffold (default engagement.json)")
    rs.set_defaults(fn=_cmd_research)

    sv = sub.add_parser("serve", help="launch the purple control center (links to ONYX)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8799)
    sv.add_argument("--no-open", action="store_true")
    sv.set_defaults(fn=_cmd_serve)

    st = sub.add_parser("selftest", help="measure extraction recall/precision on the labeled bundle")
    st.add_argument("--bundle", help="path to a labeled JS bundle (default: fixture)")
    st.set_defaults(fn=_cmd_selftest)

    ri = sub.add_parser("roe-init", help="scaffold an engagement declaration")
    ri.add_argument("--out", help="output path (default engagement.json)")
    ri.set_defaults(fn=_cmd_roe_init)

    hu = sub.add_parser("hunt", help="FIELD: real per-account HARs → offline-proven bugs "
                        "(0 requests) + EV-ranked divergence leads + dossier (optional gated live)")
    hu.add_argument("--dir", required=True, help="folder of per-account HARs (e.g. alice.har, bob.har)")
    hu.add_argument("--roe", help="engagement JSON (required, with attestation, for --live)")
    hu.add_argument("--scope", help="comma-separated in-scope hosts if no --roe")
    hu.add_argument("--authorized-by", help="authorization basis (scope URL / written grant)")
    hu.add_argument("--out", help="dossier output path (default <dir>/iolite_dossier.md)")
    hu.add_argument("--max-probes", type=int, default=300)
    hu.add_argument("--live", action="store_true",
                    help="also run the gated live intervention confirm (needs attested --roe + --target)")
    hu.add_argument("--target", help="engine intervention target.json used only with --live")
    hu.add_argument("--replay", action="store_true",
                    help="defense-aware read-side replay confirm of the EV leads (needs attested "
                         "--roe + --principals-file); adaptive-paced, parallel, scope-guarded")
    hu.add_argument("--principals-file", help="JSON {pid: {header: value}} — your own accounts' auth "
                    "headers, used only by --replay")
    hu.add_argument("--base-url", help="base URL (scheme+host) to prefix lead paths for --replay")
    hu.set_defaults(fn=_cmd_hunt)

    w = sub.add_parser("watch", help="LIVE: scan passively WHILE you browse — loopback "
                       "collector + in-page hook, instant cross-account confirmation")
    w.add_argument("--scope", help="comma-separated in-scope hosts (strongly recommended)")
    w.add_argument("--roe", help="engagement JSON (its in_scope_hosts used if --scope omitted)")
    w.add_argument("--principals", help="comma-separated account labels for the snippets (default A,B)")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8777)
    w.add_argument("--duration", type=int, help="auto-stop after N seconds (default: until Ctrl-C)")
    w.add_argument("--out", help="dossier output path (default iolite_live_dossier.md)")
    w.set_defaults(fn=_cmd_watch)

    gt = sub.add_parser("gen-target", help="auto-derive an engine intervention target.json from "
                        "captures (REVIEW _TODO before any live write-capable run)")
    gt.add_argument("--dir", required=True, help="folder of per-account HARs")
    gt.add_argument("--scope", help="comma-separated in-scope hosts")
    gt.add_argument("--principals-file", help="JSON {pid: {header: value}} — your own accounts' auth")
    gt.add_argument("--base-url", help="base URL (scheme+host) override")
    gt.add_argument("--out", help="output path (default target.json)")
    gt.set_defaults(fn=_cmd_gen_target)

    sm = sub.add_parser("sim", help="INTERNAL synthetic readiness sim vs hardened-target models "
                        "(CDN WAF, bot challenge, rate limit, token expiry) — no real traffic")
    sm.add_argument("--seed", type=int, default=7, help="deterministic seed (default 7)")
    sm.add_argument("--out", help="write the markdown readiness report to this path")
    sm.set_defaults(fn=_cmd_sim)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
