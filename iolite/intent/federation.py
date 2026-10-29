"""
federation.py — acquire the IDENTITY / FEDERATION surface (the authz machine itself).

Everything upstream models what a request does to an OBJECT. But the critical 2025 authz
zero-days on hyperscale targets lived one layer below: the IDENTITY layer — the OAuth/OIDC
authorization server, the token endpoint, the claims a service trusts as identity. IOLITE
never acquired this as a surface (the auth paths were mined only as generic endpoints), so
ONYX had nothing identity-shaped to test.

This miner reads it from evidence the target LEGALLY exposes — its own JS/HAR, already-mined
endpoints, and the (decoded, UNVERIFIED) JWTs the operator's own sessions already carry —
and emits a `FederationSurface`: the authz-server endpoints, the identity provider +
protocol, the claim keys used as identity, and propose-only identity-authz LEADS (aud/claim
trust, missing state/nonce, cross-tenant sub). PASSIVE by construction: nothing is fetched;
`.well-known`/jwks are emitted as ROE-gated leads, never probed here. Propose, never adjudicate
(QL5). Deterministic (QL4). Own evidence only (QL6).
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

# endpoint role -> matcher (first match wins; ordered most-specific first)
_FED_ROLES = (
    ("discovery", re.compile(r"/\.well-known/(openid-configuration|oauth-authorization-server)", re.I)),
    ("jwks",      re.compile(r"/\.well-known/jwks|/jwks(\.json)?(/|$)|/keys(/|$)", re.I)),
    ("authorize", re.compile(r"/(oauth2?/)?authorize(/|$)|/connect/authorize", re.I)),
    ("token",     re.compile(r"/(oauth2?/)?token(/|$)|/connect/token|/oauth/access_token", re.I)),
    ("userinfo",  re.compile(r"/userinfo(/|$)|/connect/userinfo|/me/identity", re.I)),
    ("introspect", re.compile(r"/introspect(/|$)", re.I)),
    ("revoke",    re.compile(r"/revoke(/|$)", re.I)),
    ("saml",      re.compile(r"/saml2?(/|$)|/sso/saml|/acs(/|$)|/samlacs", re.I)),
    ("callback",  re.compile(r"/callback(/|$)|/oauth/callback|/auth/callback|/signin-oidc", re.I)),
    ("logout",    re.compile(r"/logout(/|$)|/signout|/sign-out|/connect/endsession", re.I)),
    ("login",     re.compile(r"/login(/|$)|/signin|/sign-in|/auth/login|/sessions(/|$)", re.I)),
    ("sso",       re.compile(r"/sso(/|$)", re.I)),
)

_IDP_VENDORS = (
    ("auth0.com", "Auth0"), ("okta.com", "Okta"), ("oktapreview.com", "Okta"),
    ("cognito-idp", "Amazon Cognito"), ("amazoncognito.com", "Amazon Cognito"),
    ("b2clogin.com", "Azure AD B2C"), ("login.microsoftonline.com", "Azure AD"),
    ("sts.windows.net", "Azure AD"), ("accounts.google.com", "Google"),
    ("identitytoolkit", "Firebase"), ("firebaseapp.com", "Firebase"),
    ("keycloak", "Keycloak"), ("onelogin.com", "OneLogin"),
    ("pingone.com", "Ping"), ("pingidentity.com", "Ping"), ("gitlab", "GitLab"),
)

_IDENTITY_CLAIMS = frozenset((
    "sub", "email", "oid", "tid", "groups", "roles", "role", "scope", "scopes",
    "aud", "azp", "iss", "preferred_username", "upn", "name", "client_id", "cid",
    "org_id", "tenant_id", "amr", "acr",
))

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")


@dataclass
class FederationSurface:
    endpoints: dict = field(default_factory=dict)    # role -> sorted[paths]
    provider: str = ""                               # inferred IdP vendor ("" if unknown)
    protocol: str = ""                               # OIDC | OAuth2 | SAML | ""
    issuer: str = ""
    identity_claims: list = field(default_factory=list)
    leads: list = field(default_factory=list)        # ROE-gated surfaces to fetch next
    hypotheses: list = field(default_factory=list)    # propose-only identity-authz leads

    @property
    def present(self) -> bool:
        return bool(self.endpoints or self.provider or self.identity_claims)


def _jwt_payload(tok: str) -> dict:
    """Decode (NOT verify) a JWT's payload claims. {} on anything malformed."""
    parts = str(tok).split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(seg.encode()))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _host(url: str) -> str:
    m = re.search(r"https?://([^/]+)", str(url))
    return (m.group(1) if m else "").lower()


def _vendor(*texts) -> str:
    blob = " ".join(str(t).lower() for t in texts if t)
    for needle, name in _IDP_VENDORS:
        if needle in blob:
            return name
    return ""


def mine_federation(model, *, exchanges=None, texts=None, authorizations=None) -> FederationSurface:
    """Build the identity/federation surface from already-acquired evidence. Deterministic."""
    fs = FederationSurface()
    roles: dict = {}
    claims: set = set()
    client_ids: set = set()
    subs_by_tenant: dict = {}

    def classify(path: str):
        for role, rx in _FED_ROLES:
            if rx.search(str(path)):
                roles.setdefault(role, set()).add(str(path))
                return

    for ep in getattr(model, "endpoints", {}).values():
        classify(getattr(ep, "path", ""))

    blobs = list(texts or [])
    # harvest JWTs + discovery fields from any provided text, exchanges, and auth headers
    for e in (exchanges or []):
        for v in list(getattr(e, "response_fields", {}).values()):
            blobs.append(str(v))
        for k in getattr(e, "response_fields", {}):
            if str(k).lower() in _IDENTITY_CLAIMS:
                claims.add(str(k).lower())
    for a in (authorizations or []):
        blobs.append(str(a))

    issuer = ""
    for b in blobs:
        bs = str(b)
        # OIDC discovery document fields (when the operator captured one)
        mi = re.search(r'"issuer"\s*:\s*"([^"]+)"', bs)
        if mi and not issuer:
            issuer = mi.group(1)
        for mu in re.finditer(r'"(jwks_uri|authorization_endpoint|token_endpoint|userinfo_endpoint)"\s*:\s*"([^"]+)"', bs):
            classify(mu.group(2))
        for tok in _JWT_RE.findall(bs):
            pl = _jwt_payload(tok)
            for ck in pl:
                if str(ck).lower() in _IDENTITY_CLAIMS:
                    claims.add(str(ck).lower())
            if pl.get("iss") and not issuer:
                issuer = str(pl["iss"])
            for c in ("aud", "azp", "client_id", "cid"):
                if pl.get(c):
                    client_ids.add(str(pl[c]))
            if pl.get("sub") and (pl.get("tid") or pl.get("tenant_id") or pl.get("org_id")):
                t = str(pl.get("tid") or pl.get("tenant_id") or pl.get("org_id"))
                subs_by_tenant.setdefault(str(pl["sub"]), set()).add(t)

    fs.endpoints = {r: sorted(v) for r, v in sorted(roles.items())}
    fs.issuer = issuer
    fs.identity_claims = sorted(claims)
    fs.provider = _vendor(issuer, " ".join(sum(fs.endpoints.values(), [])), *(blobs[:50]))

    # protocol
    if "saml" in roles:
        fs.protocol = "SAML"
    elif "discovery" in roles or "openid" in " ".join(claims) or {"authorize", "token"} <= set(roles):
        fs.protocol = "OIDC" if ("sub" in claims or "discovery" in roles) else "OAuth2"

    # ROE-gated leads (what to fetch next, never fetched here)
    for r in ("discovery", "jwks", "authorize", "token", "userinfo"):
        for p in fs.endpoints.get(r, []):
            fs.leads.append(f"{r}: {p}")

    # propose-only identity-authz hypotheses (ONYX / operator confirms)
    H = fs.hypotheses
    if "authorize" in roles:
        H.append("authorize endpoint present → verify state/nonce (CSRF/replay) and "
                 "redirect_uri allow-listing (identity) under ROE")
    if len(client_ids) > 1:
        H.append(f"multiple token audiences/clients observed {sorted(client_ids)[:3]} → test "
                 "token-audience confusion (aud/azp not validated at the resource)")
    cross = sorted(s for s, ts in subs_by_tenant.items() if len(ts) > 1)
    if cross:
        H.append(f"subject {cross[:2]} seen across tenants → test cross-tenant identity "
                 "collision (sub not scoped by tenant)")
    if "discovery" in roles or "jwks" in roles:
        H.append("OIDC discovery / jwks exposed → map the identity oracle (algs, iss, "
                 "key rotation) under ROE for signature/issuer-trust tests")
    return fs
