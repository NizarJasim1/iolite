"""
reason · quickwins — a passive income stream. Ordinary but PAYABLE bugs that already
sit in the surface you legally captured (served JS, your own HAR responses). No
packets are sent; every finding cites the artifact it came from. These are NOT ONYX
Δstate findings — they are self-evident passive evidence, labelled as such.

Detectors:
  * secrets in JS       AWS / Google / Stripe / GitHub / Slack keys, private keys, JWT
  * verbose errors      stack traces / SQL errors / debug dumps in responses
  * CORS misconfig       ACAO:* with credentials, or a reflected arbitrary origin
  * exposed path refs    /.env /.git /backup /actuator … referenced in client code

Deterministic (QL4). Secrets are redacted in the evidence (middle masked).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("Stripe live key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical"),
    ("GitHub token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical"),
    ("Generic API secret", re.compile(
        r"['\"]?(?:api[_-]?key|apikey|secret|access[_-]?token|client[_-]?secret)['\"]?\s*[:=]\s*"
        r"['\"]([A-Za-z0-9_\-]{20,})['\"]", re.IGNORECASE), "medium"),
]
_ERROR_MARKERS = ("traceback (most recent call last)", "at java.", "at org.",
                  "exception in thread", "sqlstate", "ora-0", "you have an error in your sql",
                  "fatal error:", "warning: ", "stack trace", "system.web",
                  ".rb:", "node_modules", "goroutine ", "panic:")
_EXPOSED_REFS = ("/.env", "/.git", "/.svn", "/backup", "/config.json", "/actuator",
                 "/debug", "/.aws", "/id_rsa", "/dump", "/swagger", "/.htpasswd",
                 "/phpinfo", "/server-status")


@dataclass
class QuickWin:
    kind: str
    severity: str
    where: str                 # file/endpoint
    evidence: str
    confidence: str = "medium"
    is_lead: bool = False      # needs a live confirm (not self-evident)


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return s[:2] + "…"
    return s[:4] + "…" + s[-4:]


def _scan_secrets(text: str, where: str) -> list[QuickWin]:
    out = []
    for name, rx, sev in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            tok = m.group(1) if m.groups() else m.group(0)
            out.append(QuickWin(kind=f"Secret disclosure: {name}", severity=sev,
                                where=where, evidence=f"{name} `{_redact(tok)}` in {where}",
                                confidence="high" if sev != "medium" else "medium"))
    return out


def _scan_exposed_refs(text: str, where: str) -> list[QuickWin]:
    out, seen = [], set()
    low = text.lower()
    for ref in _EXPOSED_REFS:
        if ref in low and ref not in seen:
            seen.add(ref)
            out.append(QuickWin(kind=f"Sensitive path referenced: {ref}", severity="medium",
                                where=where, evidence=f"reference to `{ref}` in {where}",
                                confidence="low", is_lead=True))
    return out


def _iter_har_responses(text: str):
    try:
        doc = json.loads(text)
    except ValueError:
        return
    for e in (((doc or {}).get("log") or {}).get("entries") or []):
        try:
            req = e.get("request", {})
            resp = e.get("response", {})
            url = req.get("url", "")
            path = re.sub(r"^https?://[^/]+", "", url).split("?")[0] or "/"
            headers = {h.get("name", "").lower(): h.get("value", "")
                       for h in (resp.get("headers") or [])}
            body = ((resp.get("content") or {}).get("text") or "")
            yield req.get("method", "GET"), path, int(resp.get("status", 0) or 0), headers, body
        except Exception:      # noqa: BLE001
            continue


def _scan_har(text: str) -> list[QuickWin]:
    out = []
    for method, path, status, headers, body in _iter_har_responses(text):
        where = f"{method} {path}"
        low = (body or "")[:6000].lower()
        if any(mk in low for mk in _ERROR_MARKERS) or (status >= 500 and body):
            out.append(QuickWin(kind="Verbose error / stack-trace disclosure", severity="low",
                                where=where, evidence=f"error/debug output in response ({status})",
                                confidence="medium"))
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            out.append(QuickWin(kind="CORS misconfiguration (wildcard + credentials)",
                                severity="high", where=where,
                                evidence="ACAO:* with ACAC:true", confidence="high"))
        elif acao and acao not in ("*", "null") and acac == "true":
            out.append(QuickWin(kind="CORS: credentials with reflected origin", severity="medium",
                                where=where, evidence=f"ACAO:{acao} with ACAC:true",
                                confidence="medium", is_lead=True))
        # secrets sometimes echoed in responses too
        out.extend(_scan_secrets(body or "", where))
    return out


def detect(js_texts: list[str] | None = None, js_labels: list[str] | None = None,
           har_paths: list[str] | None = None) -> list[QuickWin]:
    out: list[QuickWin] = []
    js_texts = js_texts or []
    js_labels = js_labels or [f"js#{i}" for i in range(len(js_texts))]
    for text, label in zip(js_texts, js_labels, strict=False):
        if not text:
            continue
        out.extend(_scan_secrets(text, label))
        out.extend(_scan_exposed_refs(text, label))
    for hp in (har_paths or []):
        try:
            with open(hp, "r", encoding="utf-8", errors="replace") as fh:
                out.extend(_scan_har(fh.read()))
        except OSError:
            continue
    # dedup, deterministic
    seen, dedup = set(), []
    for q in out:
        sig = (q.kind, q.where, q.evidence)
        if sig in seen:
            continue
        seen.add(sig)
        dedup.append(q)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    dedup.sort(key=lambda q: (order.get(q.severity, 9), q.kind, q.where))
    return dedup


def detect_from_inputs(inputs) -> list[QuickWin]:
    """Convenience: pull JS/HAR paths from a pipeline.Inputs and scan them."""
    if inputs is None:
        return []
    js_paths = (list(getattr(inputs, "js_files", []) or []) +
                list(getattr(inputs, "archived_js_files", []) or []))
    texts, labels = [], []
    for p in js_paths:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                texts.append(fh.read()); labels.append(p)
        except OSError:
            continue
    return detect(js_texts=texts, js_labels=labels,
                  har_paths=list(getattr(inputs, "har_files", []) or []))
