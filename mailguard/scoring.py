from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse
import ipaddress


from mailguard.parser import EmailInvestigation


SUSPICIOUS_KEYWORDS = {
    "urgent",
    "verify",
    "password",
    "reset",
    "login",
    "account",
    "invoice",
    "payment",
    "wire",
    "bank",
    "security",
    "suspended",
    "limited",
    "gift card",
    "crypto",
}


RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".hta",
    ".lnk",
    ".iso",
    ".img",
    ".html",
    ".docm",
    ".xlsm",
}


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}


@dataclass
class Finding:
    points: int
    message: str


@dataclass
class RiskAssessment:
    score: int
    verdict: str
    findings: list[Finding]


def assess_email(email: EmailInvestigation) -> RiskAssessment:
    findings: list[Finding] = []

    check_authentication(email, findings)
    check_sender_mismatch(email, findings)
    check_content_keywords(email, findings)
    check_links(email, findings)
    check_attachments(email, findings)
    check_message_id(email, findings)

    score = min(sum(finding.points for finding in findings), 100)
    verdict = classify_score(score)

    return RiskAssessment(score=score, verdict=verdict, findings=findings)


def classify_score(score: int) -> str:
    if score >= 66:
        return "High risk"
    if score >= 31:
        return "Suspicious"
    return "Low risk"


def add_finding(findings: list[Finding], points: int, message: str) -> None:
    findings.append(Finding(points=points, message=message))


def check_authentication(email: EmailInvestigation, findings: list[Finding]) -> None:
    auth_text = " ".join(email.authentication_results).lower()

    if not auth_text:
        add_finding(findings, 10, "Authentication-Results header is missing")
        return

    if "spf=fail" in auth_text or "spf=softfail" in auth_text:
        add_finding(findings, 20, "SPF failed")

    if "dkim=fail" in auth_text:
        add_finding(findings, 20, "DKIM failed")
    elif "dkim=none" in auth_text:
        add_finding(findings, 15, "DKIM missing")

    if "dmarc=fail" in auth_text:
        add_finding(findings, 25, "DMARC failed")


def check_sender_mismatch(email: EmailInvestigation, findings: list[Finding]) -> None:
    from_domain = extract_email_domain(email.from_address)
    reply_to_domain = extract_email_domain(email.reply_to)
    return_path_domain = extract_email_domain(email.return_path)

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        add_finding(
            findings,
            20,
            f"Reply-To domain differs from From domain: {reply_to_domain} != {from_domain}",
        )

    if from_domain and return_path_domain and from_domain != return_path_domain:
        add_finding(
            findings,
            15,
            f"Return-Path domain differs from From domain: {return_path_domain} != {from_domain}",
        )


def check_content_keywords(email: EmailInvestigation, findings: list[Finding]) -> None:
    content = f"{email.subject} {email.text_body}".lower()

    matched_keywords = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in content
    )

    for keyword in matched_keywords[:5]:
        add_finding(findings, 5, f"Suspicious keyword found: {keyword}")


def check_links(email: EmailInvestigation, findings: list[Finding]) -> None:
    for link in email.links:
        parsed = urlparse(link)
        host = parsed.hostname or ""

        if parsed.scheme == "http":
            add_finding(findings, 10, f"Link does not use HTTPS: {link}")

        if is_ip_address(host):
            add_finding(findings, 20, f"Link uses an IP address instead of a domain: {link}")

        if host.lower() in URL_SHORTENERS:
            add_finding(findings, 15, f"URL shortener found: {host}")

        if host.count(".") >= 4:
            add_finding(findings, 10, f"Link has many subdomains: {host}")

        link_text = link.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in link_text:
                add_finding(findings, 5, f"Suspicious link keyword found: {keyword}")
                break


def check_attachments(email: EmailInvestigation, findings: list[Finding]) -> None:
    for attachment in email.attachments:
        extension = Path(attachment.filename).suffix.lower()

        if extension in RISKY_ATTACHMENT_EXTENSIONS:
            add_finding(
                findings,
                30,
                f"Risky attachment type found: {attachment.filename}",
            )
        elif attachment.filename != "unknown":
            add_finding(findings, 5, f"Attachment found: {attachment.filename}")


def check_message_id(email: EmailInvestigation, findings: list[Finding]) -> None:
    if not email.message_id:
        add_finding(findings, 5, "Message-ID header is missing")


def extract_email_domain(header_value: str) -> str:
    if not header_value:
        return ""

    _, email_address = parseaddr(header_value)
    if "@" not in email_address:
        return ""

    return email_address.split("@", 1)[1].lower().strip(">")


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False