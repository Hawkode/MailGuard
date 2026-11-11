"""Find links that are written without http:// or https://.

Phishing emails often print the link as plain text ("copy and paste this
into your browser") so that link scanners and Safe Links rewriting never
see a clickable URL. Those links are invisible to a scheme-only regex.
"""
from __future__ import annotations

import re

# Common TLDs seen in business mail and phishing. A curated set keeps
# false positives low (file names like invoice.pdf or logo.png never match)
# without needing a public-suffix download.
KNOWN_TLDS = {
    # generic
    "com", "net", "org", "info", "biz", "io", "co", "me", "app", "dev",
    "page", "site", "online", "store", "shop", "xyz", "top", "click",
    "link", "live", "life", "world", "tech", "cloud", "email", "support",
    "services", "help", "digital", "website", "space", "fun", "icu",
    "buzz", "rest", "cfd", "sbs", "lol", "mom", "cyou", "work", "today",
    "ai", "ly", "gl", "to", "cc", "ws", "tv", "gd", "su",
    # country codes common in UK and EU mail and abuse
    "uk", "ie", "eu", "de", "fr", "nl", "be", "es", "it", "pl", "ro",
    "pt", "se", "no", "dk", "fi", "ch", "at", "cz", "hu", "gr",
    "us", "ca", "au", "nz", "in", "cn", "ru", "ua", "br", "mx", "za",
    "ng", "tr", "jp", "kr", "sg", "hk", "id", "vn", "th", "my", "ph",
    # reserved for documentation (RFC 2606), used by the test samples
    "example",
}

# A hostname: labels separated by dots, ending in a letter-only TLD,
# optionally followed by a path. The lookbehind stops matches inside
# email addresses (user@domain), other hostnames and existing URLs.
BARE_HOST_PATTERN = re.compile(
    r"(?<![@\w.\-/:])"
    r"((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))"
    r"(/[^\s\"'<>]*)?",
    re.IGNORECASE,
)

TRAILING_PUNCTUATION = ".,);:]!?'\""

COPY_PASTE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"copy\s+(?:and|&)\s+paste",
        r"paste\s+(?:it|this|the\s+(?:link|address|url))\s+into",
        r"type\s+(?:this|the)\s+(?:link|address|url)\s+into",
        r"if\s+the\s+link\s+(?:does\s*n[o']t|doesn't|won't|will\s+not)\s+(?:open|work)",
    )
]


# Second-level labels under a country code, e.g. example.co.uk.
SECOND_LEVEL_LABELS = {"co", "org", "ac", "gov", "ltd", "plc", "me", "net", "com", "nhs", "sch"}


def registered_domain(host: str) -> str:
    """Return the domain an organisation registers: mail.example.co.uk -> example.co.uk."""
    labels = [label for label in (host or "").lower().strip(".").split(".") if label]

    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_LABELS:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def extract_bare_links(text: str, known_hosts: set[str] | None = None) -> list[str]:
    """Return hostnames (with path) written without a scheme.

    known_hosts holds hosts already found as full URLs, so the same
    link is not reported twice.
    """
    known_hosts = {h.lower() for h in (known_hosts or set())}
    found: set[str] = set()

    for match in BARE_HOST_PATTERN.finditer(text or ""):
        host = match.group(1).lower().rstrip(".")
        tld = match.group(2).lower()
        path = (match.group(3) or "").rstrip(TRAILING_PUNCTUATION)

        if tld not in KNOWN_TLDS:
            continue

        if host in known_hosts:
            continue

        found.add(host + path)

    return sorted(found)


def has_copy_paste_instruction(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in COPY_PASTE_PATTERNS)
