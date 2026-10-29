"""
① Passive acquisition — zero-touch OSINT (QL2).

These sources never touch the target: they read public archives and transparency
logs. The functions here parse artifacts you already pulled (offline, deterministic)
and expose thin optional LIVE wrappers (require the `live` extra + network) that
fetch them for you. Everything is filtered through the Scope-Guard before use.

Offline parsers (always available):
  * subdomains_from_ct(json_text)        — crt.sh JSON dump -> hostnames
  * urls_from_wayback(text)              — Wayback CDX / gau line list -> URLs
  * js_urls(urls)                        — filter a URL list to .js assets

Live wrappers (need requests + allowed network; used only for in-scope hosts):
  * fetch_ct(domain), fetch_wayback(domain), fetch_text(url)
"""

from __future__ import annotations

import json
import re

_JS_RE = re.compile(r"\.js(?:$|\?)", re.IGNORECASE)


def subdomains_from_ct(json_text: str) -> list[str]:
    """Parse a crt.sh JSON response into a sorted unique hostname list."""
    try:
        data = json.loads(json_text)
    except Exception:
        return []
    hosts: set[str] = set()
    for row in data if isinstance(data, list) else []:
        for field in ("common_name", "name_value"):
            val = (row or {}).get(field, "")
            for name in str(val).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and "." in name and " " not in name:
                    hosts.add(name)
    return sorted(hosts)


def urls_from_wayback(text: str) -> list[str]:
    """Parse a Wayback CDX dump or a gau/waymore line list into unique URLs."""
    urls: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # CDX rows are space-separated with the original URL as a field
        for tok in line.split():
            if tok.startswith("http://") or tok.startswith("https://"):
                urls.add(tok)
                break
        else:
            if line.startswith("http"):
                urls.add(line)
    return sorted(urls)


def js_urls(urls) -> list[str]:
    return sorted({u for u in (urls or []) if _JS_RE.search(u)})


# --------------------------------------------------------------------------- #
# LIVE wrappers — opt-in, in-scope only. Import requests lazily so the core    #
# stays pure-stdlib and offline.                                               #
# --------------------------------------------------------------------------- #

def _requests():
    try:
        import requests  # noqa
        return requests
    except Exception as e:  # pragma: no cover - env dependent
        raise RuntimeError("live acquisition needs the 'live' extra: pip install "
                           "iolite[live]") from e


def fetch_ct(domain: str, timeout: int = 30) -> list[str]:  # pragma: no cover - network
    r = _requests().get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
    return subdomains_from_ct(r.text)


def fetch_wayback(domain: str, timeout: int = 60) -> list[str]:  # pragma: no cover
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=text&fl=original&collapse=urlkey")
    r = _requests().get(url, timeout=timeout)
    return urls_from_wayback(r.text)


def fetch_text(url: str, timeout: int = 30) -> str:  # pragma: no cover - network
    return _requests().get(url, timeout=timeout).text
