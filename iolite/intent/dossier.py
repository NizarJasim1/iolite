"""
dossier.py — turn a HuntReport into a submittable Markdown report.

Two sections, in priority order:
  1. CONFIRMED (offline) — bugs PROVEN from your own captures with zero requests, each
     with a copy-pasteable PoC and the Δstate proof. These are ready to write up.
  2. EV-RANKED LEADS — the scanner-blind divergence candidates, each with the exact probe
     (method, path, which of your principals), the intent-deny derivation (why it should be
     refused), and the one command to confirm it live. No verdict is claimed for a lead.

Deterministic. Nothing here sends traffic.
"""
from __future__ import annotations

_CLASS = {
    "read_bola": "API1:2023 Broken Object Level Authorization (BOLA)",
    "action_bola": "API1:2023 BOLA (state-changing: write/delete)",
    "bopla_field": "API3:2023 Broken Object Property Level Authorization (BOPLA)",
    "rebinding": "API3:2023 BOPLA (object rebinding via client-supplied ownership field)",
    "workflow_state": "API1:2023 BOLA (workflow-context / terminal-state)",
    "chained": "API1:2023 BOLA (chained id disclosure)",
    "tenant": "API1:2023 BOLA (cross-tenant isolation)",
    "vertical": "API5:2023 Broken Function Level Authorization (BFLA)",
}


def render(report, *, program: str = "") -> str:
    L = []
    L.append(f"# IOLITE — authorization hunt dossier{(' · ' + program) if program else ''}")
    L.append("")
    L.append(f"- principals (your accounts): `{', '.join(report.principals) or '—'}`")
    L.append(f"- in-scope hosts: `{', '.join(report.scope_hosts) or '(none declared)'}`")
    L.append(f"- exchanges analysed: {report.exchanges}")
    L.append(f"- **confirmed offline (0 requests): {len(report.corroborated)}**  |  "
             f"EV-ranked leads: {len(report.leads)}")
    if report.schema.get("server_auth_fields") or report.schema.get("terminal_states"):
        L.append(f"- learned schema — server-authoritative: "
                 f"`{report.schema.get('server_auth_fields')}`; terminal states: "
                 f"`{report.schema.get('terminal_states')}`")
    if getattr(report, "live_status", ""):
        L.append(f"- live confirmation: {report.live_status}  (confirmed: {len(report.live_findings)})")
    L.append("")

    # 0) learned authorization policy (the contrast-learned intent model)
    lp = getattr(report, "learned_policy", {}) or {}
    types = lp.get("object_types") or {}
    if types:
        L.append("## 0 · Learned authorization policy (from observed enforcement contrast)")
        L.append("| object type | intent | enforced? | confidence | owner-allow | non-owner-deny | violations |")
        L.append("|---|---|---|---|---|---|---|")
        for t, p in sorted(types.items()):
            L.append(f"| `{t}` | {p['intent']} | {'yes' if p['enforced'] else '—'} | "
                     f"{p['confidence']} | {p['owner_allow']} | {p['nonowner_deny']} | {p['violations']} |")
        pr = lp.get("principals") or {}
        if any(v.get("role") or v.get("tenant") for v in pr.values()):
            L.append("")
            L.append("_Principals (from their own JWT claims):_ " +
                     ", ".join(f"`{k}`(role={v.get('role') or '—'},tenant={v.get('tenant') or '—'})"
                               for k, v in sorted(pr.items())))
        L.append("")

    # 1) confirmed offline
    L.append("## 1 · Confirmed offline — proven from your captures, zero requests")
    if not report.corroborated:
        L.append("_None corroborated from these captures. Capture the same object with a "
                 "second account (so one account's response shows another account's private "
                 "object) to enable zero-request confirmation._")
    for i, f in enumerate(report.corroborated, 1):
        L.append("")
        L.append(f"### {i}. [{f.severity.upper()}] {_CLASS.get(f.family, f.family)} — object `{f.object_id}`")
        L.append(f"- **What:** account `{f.attacker}` obtained `{f.owner}`'s object `{f.object_id}` at `{f.endpoint_key}`.")
        L.append(f"- **Proof (Δstate):** {f.evidence}.")
        L.append(f"- **How it was confirmed:** {f.cert.get('proof','')}")
        L.append(f"- **PoC:** replay `{f.endpoint_key}` for object `{f.object_id}` while "
                 f"authenticated as `{f.attacker}` — the response contains `{f.owner}`'s private value.")
        L.append(f"- **Impact class:** {_CLASS.get(f.family, f.family)}.")

    # 1b) live-confirmed by defense-aware replay
    cf = getattr(report, "confirm_findings", []) or []
    if cf:
        L.append("")
        L.append("## 1b · Live-confirmed (defense-aware replay) — value-presence on a clean response")
        for i, f in enumerate(cf, 1):
            L.append("")
            L.append(f"### C{i}. [{f.severity.upper()}] {_CLASS.get(f.family, f.family)} — object `{f.object_id}`")
            L.append(f"- **What:** `{f.attacker}` reproduced `{f.holder or 'the owner'}`'s private data at `{f.endpoint_key}`.")
            L.append(f"- **Proof:** {f.evidence}.")
            L.append(f"- **How:** {f.cert.get('proof','')}")
        if getattr(report, "exec_profile", None):
            ep = report.exec_profile
            L.append("")
            L.append(f"_Executor/defence: vendor={ep.get('vendor') or '—'}, safe_rate≈{ep.get('safe_rate')} req/s, "
                     f"blocks={ep.get('blocks')}, rate_limited={ep.get('rate_limited')}._")

    # 2) EV-ranked leads
    L.append("")
    L.append("## 2 · EV-ranked leads — exact probe + why intent forbids it (confirm live)")
    L.append(f"_Families generated: {report.by_family}_")
    for i, c in enumerate(report.leads[:40], 1):
        L.append("")
        L.append(f"### L{i}. [{c.severity}] {_CLASS.get(c.family, c.family)}  (${c.payout})")
        L.append(f"- **Probe:** as account `{c.attacker}` → `{c.method} {c.path}`"
                 + (f"  body=`{c.body}`" if getattr(c, 'body', None) else ""))
        if c.object_id:
            L.append(f"- **Object:** `{c.object_id}` (held by `{c.holder or '—'}`).")
        if c.field_name:
            L.append(f"- **Field:** `{c.field_name}` = `{c.field_value}`.")
        L.append(f"- **Why intent forbids it:** {c.derivation}")
        L.append(f"- **Confirm:** replay the probe as `{c.attacker}`; it is a finding only if "
                 f"the response reproduces the owner's discriminating private value (never a status code).")
    L.append("")

    # 3) live intervention findings (if any)
    if report.live_findings:
        L.append("## 3 · Live intervention — confirmed by Δstate")
        for i, f in enumerate(report.live_findings, 1):
            L.append(f"### LV{i}. [FINDING] {f.kind}")
            L.append(f"- {f.why}")
            if getattr(f, "read_as_B", ""):
                L.append(f"- **PoC:** as B → `GET {f.read_as_B}`")
            if getattr(f, "proof", None):
                L.append(f"- **proof:** `{f.proof}`")
        L.append("")

    L.append("---")
    L.append("_Generated by IOLITE. Offline findings sent no traffic. Leads require a "
             "scope-guarded, rate-governed, own-accounts-only replay on an authorized target._")
    return "\n".join(L)
