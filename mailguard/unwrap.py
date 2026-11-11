"""Recover the real target of links rewritten by email security gateways.

Exchange Online Safe Links, Proofpoint URL Defense and Barracuda rewrite
every link to point at their own servers. Judging the wrapper instead of
the target makes every link look like Microsoft's or Proofpoint's.
Open redirects such as google.com/url?q= are unwrapped too: attackers use
them to hide the real destination behind a trusted domain.

Nothing here visits a link. All decoding is done on the URL text.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse
import re

MAX_DEPTH = 3


@dataclass
class UnwrappedLink:
    original: str
    target: str
    wrappers: list[str]


@dataclass
class _Wrapper:
    name: str
    trusted: bool  # True when the wrapper is a security gateway, not an open redirect


SAFE_LINKS = _Wrapper("Microsoft Safe Links", True)
PROOFPOINT = _Wrapper("Proofpoint URL Defense", True)
BARRACUDA = _Wrapper("Barracuda Link Protection", True)
GOOGLE_REDIRECT = _Wrapper("Google redirect", False)

OPAQUE_WRAPPERS = {
    "mimecast.com": "Mimecast URL Protect",
}

PROOFPOINT_V3 = re.compile(r"^https?://urldefense\.com/v3/__(.+?)__;", re.IGNORECASE)


def unwrap_url(url: str) -> UnwrappedLink:
    """Peel off known wrappers, up to MAX_DEPTH layers."""
    current = url
    wrappers: list[str] = []

    for _ in range(MAX_DEPTH):
        result = _unwrap_once(current)
        if result is None:
            break
        wrapper, inner = result
        wrappers.append(wrapper.name)
        current = inner

    return UnwrappedLink(original=url, target=current, wrappers=wrappers)


def is_open_redirect(name: str) -> bool:
    return name == GOOGLE_REDIRECT.name


def opaque_wrapper(url: str) -> str | None:
    """Name of a wrapper whose target cannot be decoded offline."""
    host = (urlparse(url).hostname or "").lower()
    for domain, name in OPAQUE_WRAPPERS.items():
        if host == domain or host.endswith("." + domain):
            return name
    return None


def _unwrap_once(url: str) -> tuple[_Wrapper, str] | None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    query = parse_qs(parsed.query)

    if host.endswith("safelinks.protection.outlook.com") and "url" in query:
        return SAFE_LINKS, query["url"][0]

    if host == "urldefense.proofpoint.com" and parsed.path.startswith("/v2/url") and "u" in query:
        encoded = query["u"][0].replace("-", "%").replace("_", "/")
        return PROOFPOINT, unquote(encoded)

    v3 = PROOFPOINT_V3.match(url)
    if v3:
        # v3 replaces some characters with "*" markers; the host survives intact.
        return PROOFPOINT, v3.group(1)

    if host == "linkprotect.cudasvc.com" and "a" in query:
        return BARRACUDA, query["a"][0]

    if host in {"google.com", "www.google.com"} and parsed.path == "/url":
        target = (query.get("q") or query.get("url") or [None])[0]
        if target and target.lower().startswith(("http://", "https://")):
            return GOOGLE_REDIRECT, target

    return None
