"""Parse SPF, DKIM and DMARC results and check alignment with the From domain.

Only the topmost Authentication-Results header is used. It is the one the
receiving server added; copies lower down come from earlier hops or were
written by the sender, who can put anything there.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

from mailguard.links import registered_domain


@dataclass
class AuthResults:
    present: bool = False
    spf: str = ""
    spf_domain: str = ""
    dkim: list[str] = field(default_factory=list)
    dkim_domains: list[str] = field(default_factory=list)
    dmarc: str = ""
    dmarc_action: str = ""
    header_from: str = ""

    def spf_aligned(self, from_domain: str) -> bool:
        return (
            self.spf == "pass"
            and bool(from_domain)
            and registered_domain(self.spf_domain) == registered_domain(from_domain)
        )

    def dkim_aligned(self, from_domain: str) -> bool:
        if not from_domain:
            return False
        target = registered_domain(from_domain)
        return any(
            result == "pass" and registered_domain(domain) == target
            for result, domain in zip(self.dkim, self.dkim_domains)
        )

    def aligned(self, from_domain: str) -> bool:
        """Relaxed DMARC alignment: SPF or DKIM passed for the From domain."""
        return self.dmarc == "pass" or self.spf_aligned(from_domain) or self.dkim_aligned(from_domain)


def _first(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(1).lower().strip(";") if match else ""


def parse_authentication_results(headers: list[str]) -> AuthResults:
    if not headers:
        return AuthResults()

    text = re.sub(r"\s+", " ", str(headers[0]))

    dkim_results = [r.lower() for r in re.findall(r"\bdkim=(\w+)", text, re.IGNORECASE)]
    dkim_domains = [d.lower().strip(";") for d in re.findall(r"header\.d=([^\s;]+)", text, re.IGNORECASE)]
    # Pad so each DKIM result has a domain slot, even if one is missing.
    dkim_domains += [""] * (len(dkim_results) - len(dkim_domains))

    return AuthResults(
        present=True,
        spf=_first(r"\bspf=(\w+)", text),
        spf_domain=_first(r"smtp\.mailfrom=([^\s;]+)", text).split("@")[-1],
        dkim=dkim_results,
        dkim_domains=dkim_domains,
        dmarc=_first(r"\bdmarc=(\w+)", text),
        dmarc_action=_first(r"\baction=([\w.]+)", text),
        header_from=_first(r"header\.from=([^\s;]+)", text),
    )
