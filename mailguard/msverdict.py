"""Read the verdict Exchange Online Protection already stamped on a message.

Every message delivered through Microsoft 365 carries Microsoft's own
analysis in its headers. Reading it costs nothing and needs no API.

Field meanings follow Microsoft Learn, "Anti-spam message headers in
Microsoft 365". In cloud organisations SCL does not decide the action,
so MailGuard scores CAT, SFTY, SFV and compauth, and shows SCL and BCL
for context.

Only the topmost copy of each header is read: it is the one added by the
receiving tenant. Copies further down may come from earlier hops or be
planted by the sender.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

CATEGORY_NAMES = {
    "AMP": "Anti-malware",
    "BIMP": "Brand impersonation",
    "BULK": "Bulk",
    "DIMP": "Domain impersonation",
    "FTBP": "Anti-malware common attachments filter",
    "GIMP": "Mailbox intelligence impersonation",
    "HPHSH": "High confidence phishing",
    "HPHISH": "High confidence phishing",
    "HSPM": "High confidence spam",
    "INTOS": "Intra-organisation phishing",
    "MALW": "Malware",
    "OSPM": "Outbound spam",
    "PHSH": "Phishing",
    "SAP": "Safe Attachments",
    "SPM": "Spam",
    "SPOOF": "Spoofing",
    "UIMP": "User impersonation",
    "NONE": "No threat category",
}

# Risk points per category. Phishing, malware and impersonation weigh
# more than spam because they are the ones that lead to account takeover.
CATEGORY_POINTS = {
    "HPHSH": 60,
    "HPHISH": 60,
    "MALW": 60,
    "AMP": 60,
    "SAP": 60,
    "FTBP": 40,
    "PHSH": 45,
    "INTOS": 40,
    "UIMP": 40,
    "DIMP": 40,
    "GIMP": 35,
    "BIMP": 40,
    "SPOOF": 35,
    "HSPM": 20,
    "SPM": 15,
    "BULK": 5,
}

SFV_MEANINGS = {
    "BLK": "Blocked: sender is in the user's Blocked Senders list",
    "NSPM": "Spam filtering marked the message as not spam",
    "SFE": "Filtering skipped: sender is in the user's Safe Senders list",
    "SKA": "Filtering skipped: sender is in an anti-spam policy allow list",
    "SKB": "Marked as spam: sender matched an anti-spam policy block list",
    "SKI": "Filtering skipped: source IP is in the connection filter IP Allow List",
    "SKN": "Filtering skipped: a mail flow (transport) rule bypassed spam filtering",
    "SKQ": "Released from quarantine",
    "SKS": "Marked as spam before filtering by a mail flow rule or hybrid decision",
    "SPM": "Marked as spam by spam filtering",
}

# SFV values meaning Microsoft never judged the message.
SFV_BYPASS = {"SFE", "SKA", "SKI", "SKN"}

SFTY_MEANINGS = {
    "9.19": "Domain impersonation of a protected domain",
    "9.20": "User impersonation of a protected or internal user",
    "9.25": "First contact: the recipient has not had mail from this sender before",
}


@dataclass
class MicrosoftVerdict:
    category: str = ""
    sfv: str = ""
    scl: str = ""
    sfty: str = ""
    direction: str = ""
    connecting_ip: str = ""
    country: str = ""
    bulk: bool = False
    bcl: int | None = None
    compauth: str = ""
    compauth_reason: str = ""
    raw_fields: dict[str, str] = field(default_factory=dict)

    @property
    def category_name(self) -> str:
        return CATEGORY_NAMES.get(self.category, self.category)

    @property
    def sfv_meaning(self) -> str:
        return SFV_MEANINGS.get(self.sfv, self.sfv)

    @property
    def sfty_meaning(self) -> str:
        return SFTY_MEANINGS.get(self.sfty, self.sfty)

    @property
    def filtering_bypassed(self) -> bool:
        return self.sfv in SFV_BYPASS


def parse_forefront_report(header_value: str) -> dict[str, str]:
    """Split 'CIP:1.2.3.4;CTRY:GB;SCL:1;...' into a dict."""
    fields: dict[str, str] = {}

    for chunk in re.sub(r"\s+", "", header_value or "").split(";"):
        if ":" not in chunk:
            continue
        name, value = chunk.split(":", 1)
        if name and name.upper() not in fields:
            fields[name.upper()] = value

    return fields


def parse_bcl(header_value: str) -> int | None:
    match = re.search(r"\bBCL:(\d)", header_value or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


def parse_compauth(auth_results: str) -> tuple[str, str]:
    match = re.search(
        r"compauth=(pass|fail|softpass|none)(?:\s+reason=(\d{3}))?",
        auth_results or "",
        re.IGNORECASE,
    )
    if not match:
        return "", ""
    return match.group(1).lower(), match.group(2) or ""


def describe_compauth_reason(reason: str) -> str:
    """Meaning of a composite authentication reason code."""
    exact = {
        "000": "DMARC failed and the domain's policy is quarantine or reject",
        "001": "No usable SPF, DKIM or DMARC, or only a weak policy",
        "002": "Your organisation's policy blocks this sender from spoofing",
        "010": "Spoofs one of your own accepted domains (DMARC fail)",
        "601": "Spoofs one of your own accepted domains",
    }
    if reason in exact:
        return exact[reason]
    if reason.startswith("6"):
        return "Failed implicit email authentication"
    if reason.startswith(("1", "7")):
        return "Passed composite authentication"
    if reason.startswith("2"):
        return "Soft-passed implicit authentication"
    return ""


def read_microsoft_verdict(message) -> MicrosoftVerdict | None:
    """Return Microsoft's verdict, or None if the message has no EOP headers."""
    forefront = message.get("X-Forefront-Antispam-Report")
    antispam = message.get("X-Microsoft-Antispam")
    org_scl = message.get("X-MS-Exchange-Organization-SCL")
    auth_results = message.get("Authentication-Results")

    compauth, reason = parse_compauth(str(auth_results or ""))

    # compauth is Microsoft-only, so it proves EOP processed the message
    # even when the other headers were not included in a paste.
    if not (forefront or antispam or org_scl or compauth):
        return None

    fields = parse_forefront_report(str(forefront or ""))

    return MicrosoftVerdict(
        category=fields.get("CAT", "").upper(),
        sfv=fields.get("SFV", "").upper(),
        scl=fields.get("SCL", "") or str(org_scl or "").strip(),
        sfty=fields.get("SFTY", ""),
        direction=fields.get("DIR", "").upper(),
        connecting_ip=fields.get("CIP", ""),
        country=fields.get("CTRY", ""),
        bulk=fields.get("SRV", "").upper() == "BULK",
        bcl=parse_bcl(str(antispam or "")),
        compauth=compauth,
        compauth_reason=reason,
        raw_fields=fields,
    )
