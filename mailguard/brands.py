"""Spot display names that claim a brand the sending domain does not own.

"Royal Mail <noreply@rm-delivery-uk.com>" passes every authentication
check, because the attacker owns rm-delivery-uk.com. The lie is in the
display name, which is the only part most people read.

The domain lists cover the main sending domains of each brand. A genuine
brand email from a domain missing here will be flagged; the finding says
so, and the fix is to add the domain.
"""
from __future__ import annotations

import re

# Display name pattern -> domains the brand sends from (subdomains included).
BRANDS: dict[str, tuple[str, set[str]]] = {
    "Royal Mail": (r"royal\s*mail", {"royalmail.com", "royalmail.co.uk", "royalmailgroup.com"}),
    "Parcelforce": (r"parcel\s*force", {"parcelforce.com", "parcelforce.co.uk"}),
    "Evri": (r"\bevri\b|\bmy\s*hermes\b", {"evri.com", "myhermes.co.uk", "hermes-europe.co.uk"}),
    "DPD": (r"\bdpd\b", {"dpd.co.uk", "dpd.com", "dpdlocal.co.uk", "dpdgroup.com"}),
    "DHL": (r"\bdhl\b", {"dhl.com", "dhl.co.uk", "dhl.de"}),
    "UPS": (r"\bups\b", {"ups.com"}),
    "FedEx": (r"\bfed\s*ex\b", {"fedex.com"}),
    "Amazon": (r"\bamazon\b", {"amazon.co.uk", "amazon.com", "amazon.de", "amazon.fr", "amazon.es", "amazon.it", "amazonaws.com"}),
    "HMRC": (r"\bhmrc\b|hm\s+revenue", {"gov.uk"}),
    "DVLA": (r"\bdvla\b", {"gov.uk"}),
    "Microsoft": (
        r"\bmicrosoft\b|\boffice\s*365\b|\bmicrosoft\s*365\b|\bonedrive\b|\bsharepoint\b|\boutlook\s+(?:team|support|security)\b",
        {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "microsoft365.com", "sharepointonline.com"},
    ),
    "DocuSign": (r"docu\s*sign", {"docusign.net", "docusign.com"}),
    "Adobe": (r"\badobe\b", {"adobe.com", "adobesign.com", "echosign.com"}),
    "PayPal": (r"pay\s*pal", {"paypal.com", "paypal.co.uk"}),
    "Apple": (r"^\s*apple\s*$|\bapple\s+(?:id|support|pay|store|account)\b|\bicloud\b", {"apple.com"}),
    "Netflix": (r"\bnetflix\b", {"netflix.com"}),
    "Barclays": (r"\bbarclay", {"barclays.co.uk", "barclays.com", "barclaycard.co.uk"}),
    "HSBC": (r"\bhsbc\b", {"hsbc.co.uk", "hsbc.com"}),
    "Lloyds": (r"^\s*lloyds\s*$|\blloyds\s+bank", {"lloydsbank.co.uk", "lloydsbank.com", "lloydsbankinggroup.com"}),
    "NatWest": (r"\bnat\s*west\b", {"natwest.com", "natwestgroup.com"}),
    "Santander": (r"\bsantander\b", {"santander.co.uk"}),
    "Nationwide": (r"^\s*nationwide\s*$|\bnationwide\s+(?:building\s+society|bank)", {"nationwide.co.uk"}),
}

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def _domain_belongs(domain: str, allowed: set[str]) -> bool:
    domain = domain.lower()
    return any(domain == a or domain.endswith("." + a) for a in allowed)


def claimed_brand(display_name: str, sender_domain: str) -> str:
    """Brand named in the display name that the sending domain does not belong to."""
    for brand, (pattern, allowed) in BRANDS.items():
        if re.search(pattern, display_name or "", re.IGNORECASE):
            if not _domain_belongs(sender_domain, allowed):
                return brand
    return ""


def address_in_display_name(display_name: str, sender_domain: str) -> str:
    """An email address shown in the display name that is not the real sender's domain."""
    match = EMAIL_IN_TEXT.search(display_name or "")
    if match and match.group(1).lower() != (sender_domain or "").lower():
        return match.group(0)
    return ""
