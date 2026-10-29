"""
authz_engine.py (v3) — operational, config-driven interventional BOLA engine.

Wall-1 principle, made real: reconstruct intent by INTERVENTION (create objects
as principals we own, using the app's own affordances), then confirm an
over-permission by a SOUND value-presence Delta-state (a discriminating private
value reproduced cross-principal) -- never by a status code.

Zero target-specific code: the whole target (auth flow, object kinds,
producer/consumer endpoints, read key) is declared in a JSON target config.
Legal-by-construction: ScopeGuard on every request; own principals only; a
politeness Governor; dry-run blocks cross-principal writes.

Usage:  python3 authz_engine.py <target.json> [--report out.md]
"""
from __future__ import annotations
import json, re, sys, time, uuid, urllib.request, urllib.error
from dataclasses import dataclass, field

# ----------------------------------------------------------- legal + politeness
@dataclass
class ScopeGuard:
    allowed_hosts: set
    allow_write_hosts: set
    def check(self, host: str, method: str) -> tuple[bool, str]:
        if host not in self.allowed_hosts:
            return False, f"HALT: host {host} out of scope"
        if method in ("POST", "PUT", "PATCH", "DELETE") and host not in self.allow_write_hosts:
            return False, f"HALT: write {method} not permitted on {host} (dry-run)"
        return True, "ok"

class Governor:
    def __init__(self, min_interval: float = 0.0):
        self.min_interval, self._last = min_interval, 0.0
    def wait(self):
        dt = self.min_interval - (time.monotonic() - self._last)
        if dt > 0: time.sleep(dt)
        self._last = time.monotonic()

@dataclass
class Resp:
    status: int
    body: str
    def json(self):
        try: return json.loads(self.body)
        except Exception: return {}

class Http:
    def __init__(self, base, host, guard, gov):
        self.base, self.host, self.guard, self.gov = base, host, guard, gov
    def __call__(self, method, path, headers=None, body=None, timeout=8, retries=2) -> Resp:
        ok, why = self.guard.check(self.host, method)
        if not ok: return Resp(-2, why)
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(retries + 1):
            self.gov.wait()
            req = urllib.request.Request(self.base + path, data=data, method=method)
            for k, v in (headers or {}).items(): req.add_header(k, v)
            if data is not None: req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return Resp(r.status, r.read().decode(errors="replace"))
            except urllib.error.HTTPError as e:
                return Resp(e.code, e.read().decode(errors="replace"))
            except Exception as e:                       # noqa: BLE001 — retry transient
                if attempt == retries: return Resp(-1, str(e))
                time.sleep(0.5 * (attempt + 1))
        return Resp(-1, "unreachable")

# ----------------------------------------------------------- value model (G2)
def leaves(obj) -> set:
    out = set()
    def rec(v):
        if isinstance(v, dict):
            for x in v.values(): rec(x)
        elif isinstance(v, list):
            for x in v: rec(x)
        elif v is not None:
            out.add(str(v))
    rec(obj); return out

def _fill(tmpl, subs: dict):
    if isinstance(tmpl, str):
        for k, v in subs.items(): tmpl = tmpl.replace("{{%s}}" % k, v)
        return tmpl
    if isinstance(tmpl, dict): return {k: _fill(v, subs) for k, v in tmpl.items()}
    return tmpl

# ----------------------------------------------------------- auth (G3)
class Session:
    def __init__(self, http: Http, auth_cfg: dict, creds: dict):
        self.http, self.cfg, self.creds = http, auth_cfg, creds
        self.headers: dict = {}
    def establish(self) -> str:
        if not self.cfg.get("login"):                      # static-credential mode
            self.headers = dict(self.creds.get("headers", {}))
            return "" if self.headers else "no static headers configured"
        subs = {"user": self.creds["user"], "pass": self.creds["pass"]}
        if self.cfg.get("register"):
            self.http("POST", self.cfg["register"], body=_fill(self.cfg["reg_body"], subs))  # idempotent
        r = self.http("POST", self.cfg["login"], body=_fill(self.cfg["login_body"], subs))
        tok = r.json().get(self.cfg["token_field"], "")
        if not tok: return f"login failed ({r.status}): {r.body[:120]}"
        self.headers = {self.cfg.get("header", "Authorization"): self.cfg.get("scheme", "Bearer ") + tok}
        return ""

# ----------------------------------------------------------- engine
@dataclass
class Finding:
    kind: str; verdict: str; why: str
    read_as_B: str = ""; proof: dict = field(default_factory=dict)

class Engine:
    def __init__(self, http: Http, auth_cfg: dict, nonce: str):
        self.http, self.auth, self.nonce = http, auth_cfg, nonce

    def _create(self, kind, sess, title, secret):
        """Returns (ok, read_subs). read_subs merges what we SENT (title/secret)
        with scalar fields the create RESPONSE returned (e.g. a server-assigned id),
        so the read path can be keyed by a client value (title) OR a server id."""
        subs = {"title": title, "secret": secret}
        c = kind["create"]
        r = self.http(c["method"], _fill(c["path"], subs), headers=sess.headers,
                      body=_fill(c.get("body", {}), subs))
        rj = r.json()
        if isinstance(rj, dict):
            for k, v in rj.items():
                if isinstance(v, (str, int)):
                    subs[str(k)] = str(v)
        return r.status in (200, 201), subs

    def _read(self, kind, sess, subs) -> Resp:
        rd = kind["read"]
        return self.http(rd["method"], _fill(rd["path"], subs), headers=sess.headers)

    def run_kind(self, kind, sa: Session, sb: Session) -> Finding:
        n = self.nonce
        secretA1 = f"ONYX-SEC-A1-{n}"
        # 1. intervention: A creates A1,A2 (own) ; B creates B1 (own) — unique per run
        ok1, s1 = self._create(kind, sa, f"onyxA1{n}", secretA1)
        ok2, s2 = self._create(kind, sa, f"onyxA2{n}", f"ONYX-SEC-A2-{n}")
        okb, sb_ = self._create(kind, sb, f"onyxB1{n}", f"ONYX-SEC-B1-{n}")
        if not (ok1 and ok2 and okb):
            return Finding(kind["name"], "SKIP", "could not create the 3 control objects")
        # 2. owner control: A must reproduce A1's private value
        va1 = self._read(kind, sa, s1)
        if va1.status != 200 or secretA1 not in va1.body:
            return Finding(kind["name"], "SKIP", "owner control failed (A can't read own A1)")
        va2 = self._read(kind, sa, s2)
        vb1 = self._read(kind, sb, sb_)
        # discriminating values of A1, MINUS only what the PROBE itself supplies in
        # the read path (e.g. the id/title B puts in the URL) — never the private
        # fields we are trying to detect. (Over-subtracting here silently kills recall.)
        read_keys = set(re.findall(r"{{(\w+)}}", kind["read"]["path"]))
        supplied = {s1[k] for k in read_keys if k in s1}
        disc = (leaves(va1.json()) - leaves(va2.json()) - leaves(vb1.json())) - supplied
        # 3+4. probe: B reads A1 (manufactured-negative coordinate)
        pb = self._read(kind, sb, s1)
        if pb.status in (401, 403, 404):
            return Finding(kind["name"], "CLEAN", f"B enforced-denied ({pb.status})")
        hit = disc & leaves(pb.json())
        if hit:
            return Finding(kind["name"], "FINDING",
                           "B reproduced A's discriminating private value -> BOLA proven by Delta-state",
                           _fill(kind["read"]["path"], s1),
                           {"owner_value": sorted(disc), "attacker_reproduced": sorted(hit),
                            "attacker_status": pb.status})
        if pb.status == 200:
            return Finding(kind["name"], "ABSTAIN", "B got 200 but no discriminating value reproduced")
        return Finding(kind["name"], "CLEAN", f"B status {pb.status}")

def run_target(cfg: dict) -> list[Finding]:
    host = cfg["host"]
    guard = ScopeGuard(allowed_hosts={host}, allow_write_hosts={host})
    gov = Governor(cfg.get("min_interval", 0.0))
    http = Http(cfg["base_url"], host, guard, gov)
    sa = Session(http, cfg["auth"], cfg["principals"]["A"])
    sb = Session(http, cfg["auth"], cfg["principals"]["B"])
    for s, name in ((sa, "A"), (sb, "B")):
        err = s.establish()
        if err: raise SystemExit(f"[auth] principal {name}: {err}")
    eng = Engine(http, cfg["auth"], nonce=uuid.uuid4().hex[:8])
    return [eng.run_kind(k, sa, sb) for k in cfg["kinds"]]

def to_markdown(cfg, findings) -> str:
    lines = [f"# AuthZ Intent Engine — run report: {cfg['name']}", ""]
    nf = sum(1 for f in findings if f.verdict == "FINDING")
    lines += [f"- target: `{cfg['base_url']}`  |  kinds tested: {len(findings)}  |  **confirmed findings: {nf}**",
              "- confirmation: cross-principal value-presence Delta-state (never a status code)", ""]
    for f in findings:
        lines.append(f"## [{f.verdict}] {f.kind}")
        lines.append(f"- {f.why}")
        if f.verdict == "FINDING":
            lines += [f"- **PoC:** as principal B → `GET {f.read_as_B}` (B does not own it)",
                      f"- **Delta-state proof:** owner-private value `{f.proof['attacker_reproduced']}` "
                      f"reproduced in B's response (status {f.proof['attacker_status']})",
                      "- **class:** OWASP API1:2023 Broken Object Level Authorization (BOLA)"]
        lines.append("")
    return "\n".join(lines)

def main(argv):
    if not argv:
        print("usage: python3 -m iolite.intent <target.json> [--report out.md]"); return 2
    with open(argv[0]) as fh:
        cfg = json.load(fh)
    findings = run_target(cfg)
    print(f"AUTHZ INTENT ENGINE — target={cfg['name']}  base={cfg['base_url']}")
    print("=" * 76)
    for f in findings:
        tag = {"FINDING": "FIND ", "CLEAN": "CLEAN", "ABSTAIN": "ABST ", "SKIP": "SKIP "}[f.verdict]
        print(f"  [{tag}] {f.kind:10s} -> {f.verdict:8s} | {f.why}")
        if f.verdict == "FINDING":
            print(f"            PoC: as B -> GET {f.read_as_B}")
            print(f"            proof: {json.dumps(f.proof)}")
    print("=" * 76)
    print(f"confirmed findings: {sum(1 for f in findings if f.verdict=='FINDING')} | "
          "a 200 to B is never a finding; only a reproduced discriminating value is.")
    if "--report" in argv:
        out = argv[argv.index("--report") + 1]
        with open(out, "w") as fh:
            fh.write(to_markdown(cfg, findings))
        print(f"report written: {out}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
