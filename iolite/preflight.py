"""
preflight — the fail-CLOSED live-safety gate (Point 5, the SAFETY transfer).

Offline everything is trivially safe (no packets). The moment a run goes live it
sends real requests to a real third party, and the legal-by-construction guarantees
(own accounts · in scope · non-destructive · attested) must hold AT RUNTIME, not just
by design. A single out-of-scope or destructive live packet is catastrophic.

`preflight` verifies the whole chain BEFORE any live packet and REFUSES (fail-closed)
unless every mandatory gate is green. It sends nothing itself. Grounded in standard
authorised-testing Rules of Engagement (GitHub / MSRC / Bugcrowd). Deterministic (QL4).

Mandatory gates (must be green to go live):
  attestation · scope · principals · non-destructive · rate-governor
Live-required gate: onyx-reachable (the oracle must answer for a live confirmation).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Gate:
    name: str
    ok: bool
    detail: str
    mandatory: bool = True


@dataclass
class PreflightReport:
    gates: list[Gate] = field(default_factory=list)

    @property
    def mandatory_ok(self) -> bool:
        return all(g.ok for g in self.gates if g.mandatory)

    @property
    def onyx_ok(self) -> bool:
        return all(g.ok for g in self.gates if g.name == "onyx-reachable")

    @property
    def go(self) -> bool:
        """Safe to proceed to on-device live steps (mandatory gates green)."""
        return self.mandatory_ok

    @property
    def live_ready(self) -> bool:
        """Safe to issue live confirmation packets (mandatory + oracle green)."""
        return self.mandatory_ok and self.onyx_ok

    def red(self) -> list[Gate]:
        return [g for g in self.gates if not g.ok]

    def render(self) -> str:
        lines = []
        for g in self.gates:
            mark = "✓" if g.ok else ("✗" if g.mandatory else "·")
            tag = "" if g.mandatory else "  (advisory)"
            lines.append(f"  [{mark}] {g.name:<16} {g.detail}{tag}")
        verdict = "GO" if self.go else "NO-GO"
        if self.go and not self.onyx_ok:
            verdict = "GO (offline prep only — link ONYX before live packets)"
        return "\n".join(lines) + f"\n  ⇒ {verdict}"


def _host_matches(host: str, pattern: str) -> bool:
    h, p = host.lower().strip(), pattern.lower().strip()
    if p.startswith("*."):
        return h == p[2:] or h.endswith("." + p[2:])
    return h == p


def _in_any(host: str, patterns) -> bool:
    return any(_host_matches(host, p) for p in patterns or [])


def _placeholder(hosts) -> bool:
    return any(h.startswith("<") or "example.com" in h for h in hosts or [])


def preflight(engagement, model, spec: dict | None = None, allow_write: bool = False,
              onyx_check: bool = True) -> PreflightReport:
    """Assess live readiness. Fail-closed: any red mandatory gate ⇒ not GO. Sends no
    packets. `allow_write` = the operator explicitly intends ONE bounded, reversible-
    preferred mutation on their OWN object (still requires allow_destructive + attest)."""
    gates: list[Gate] = []

    # 1) attestation — a conscious human legal act, never auto-filled
    att = engagement.attested()
    gates.append(Gate("attestation", att,
                      "explicit written attestation + authorisation basis present"
                      if att else "MISSING/placeholder — write a real attestation in the ROE"))

    # 2) scope — every host actually seen in captures must be in-scope, none out
    hosts = sorted(getattr(model, "hosts_seen", set()) or
                   ({model.host} if getattr(model, "host", "") else set()))
    in_scope = list(getattr(engagement, "in_scope_hosts", []) or [])
    out_scope = list(getattr(engagement, "out_of_scope_hosts", []) or [])
    if not hosts:
        scope_ok, why = False, "no host resolved from captures — nothing to scope-check"
    elif _placeholder(in_scope):
        scope_ok, why = False, "in-scope hosts are still template placeholders"
    else:
        offenders = [h for h in hosts if _in_any(h, out_scope) or not _in_any(h, in_scope)]
        scope_ok = not offenders
        why = ("all captured hosts are in-scope" if scope_ok
               else f"out-of-scope / unlisted host(s): {offenders}")
    gates.append(Gate("scope", scope_ok, why))

    # 3) principals — ≥2 of YOUR OWN accounts (cross-principal proof needs two)
    n = len(getattr(model, "principals", []) or [])
    own = bool(getattr(engagement, "own_accounts_only", True))
    p_ok = n >= 2 and own
    gates.append(Gate("principals", p_ok,
                      f"{n} own principal(s), own_accounts_only={own}"
                      if p_ok else f"need ≥2 OWN accounts (have {n}, own_accounts_only={own})"))

    # 4) non-destructive — mutation suppression ON, unless an explicit bounded opt-in
    dry = bool(getattr(engagement, "dry_run", True))
    if allow_write:
        nd_ok = bool(getattr(engagement, "allow_destructive", False)) and att
        why = ("explicit bounded write opted-in (allow_destructive + attested) — one "
               "reversible-preferred write on your OWN object"
               if nd_ok else "write requested but allow_destructive/attestation not set")
    else:
        nd_ok = dry
        why = ("mutation suppression ON (dry-run) — leaks confirmed by read-back only"
               if nd_ok else "dry_run is OFF but no explicit write opt-in — unsafe default")
    gates.append(Gate("non-destructive", nd_ok, why))

    # 5) rate governor — a conservative human-paced ceiling
    rpm = int(getattr(engagement, "max_requests_per_min", 0) or 0)
    g_ok = 0 < rpm <= 120
    gates.append(Gate("rate-governor", g_ok,
                      f"{rpm} req/min (human-paced, backs off on 429/WAF)"
                      if g_ok else f"set a sane max_requests_per_min (1–120); got {rpm}"))

    # 6) onyx-reachable — the oracle must answer for a LIVE confirmation (advisory
    #    offline: prep is fine, but no live packet until ONYX is linked + parses)
    if onyx_check:
        try:
            from . import onyx_link
            if spec is not None:
                v = onyx_link.verify_spec(spec)
                o_ok = bool(v.get("available") and v.get("parses"))
                od = ("ONYX linked and parses the spec" if o_ok
                      else f"ONYX not ready: {v.get('error') or v.get('hint') or 'not linked'}")
            else:
                o_ok = onyx_link.available()
                od = "ONYX linked" if o_ok else "ONYX not linked (set ONYX_PATH)"
        except Exception as e:      # noqa: BLE001
            o_ok, od = False, f"onyx check failed: {type(e).__name__}"
        gates.append(Gate("onyx-reachable", o_ok, od, mandatory=False))

    return PreflightReport(gates=gates)
