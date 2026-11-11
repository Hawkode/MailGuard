from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import re


from mailguard.links import extract_bare_links, registered_domain
from mailguard.unwrap import is_open_redirect, opaque_wrapper
from mailguard.msverdict import CATEGORY_POINTS, describe_compauth_reason
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


# Click-tracking services used by legitimate newsletters. Their links never
# match the visible text, so a text/target mismatch says nothing on its own.
CLICK_TRACKING_DOMAINS = {
    "sendgrid.net",
    "list-manage.com",
    "mcsv.net",
    "hubspotlinks.com",
    "hs-sites.com",
    "mailgun.org",
    "sparkpostmail.com",
    "rs6.net",
    "exct.net",
    "mandrillapp.com",
    "cmail19.com",
    "cmail20.com",
    "createsend1.com",
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

    check_microsoft_verdict(email, findings)
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


def check_microsoft_verdict(email: EmailInvestigation, findings: list[Finding]) -> None:
    verdict = email.microsoft_verdict
    if verdict is None:
        return

    points = CATEGORY_POINTS.get(verdict.category, 0)
    if points:
        add_finding(
            findings,
            points,
            f"Microsoft verdict: {verdict.category_name} (CAT:{verdict.category})",
        )

    if verdict.sfty in {"9.19", "9.20"}:
        add_finding(findings, 30, f"Microsoft safety tip: {verdict.sfty_meaning}")
    elif verdict.sfty == "9.25":
        add_finding(findings, 10, f"Microsoft safety tip: {verdict.sfty_meaning}")

    if verdict.sfv == "SKB":
        add_finding(findings, 20, f"Microsoft filter: {verdict.sfv_meaning}")
    elif verdict.sfv == "BLK":
        add_finding(findings, 10, f"Microsoft filter: {verdict.sfv_meaning}")
    elif verdict.filtering_bypassed:
        # No points: an allow list is not evidence of phishing. It does mean
        # Microsoft never judged the message, which an attacker can exploit.
        add_finding(
            findings,
            0,
            f"Microsoft filter skipped, so there is no Microsoft verdict: {verdict.sfv_meaning}",
        )

    if verdict.compauth == "fail":
        meaning = describe_compauth_reason(verdict.compauth_reason)
        add_finding(
            findings,
            20,
            f"Microsoft composite authentication failed (reason {verdict.compauth_reason}): {meaning}".rstrip(": "),
        )
    elif verdict.compauth == "softpass":
        add_finding(findings, 5, "Microsoft composite authentication only soft-passed")

    if verdict.bcl is not None and verdict.bcl >= 8:
        add_finding(findings, 5, f"Bulk sender with a high number of complaints (BCL {verdict.bcl})")


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

        # Mimecast tokens cannot be decoded offline; its own hostnames are not a signal.
        if host.count(".") >= 4 and not opaque_wrapper(link):
            add_finding(findings, 10, f"Link has many subdomains: {host}")

        link_text = link.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in link_text:
                add_finding(findings, 5, f"Suspicious link keyword found: {keyword}")
                break

    for wrapped in email.wrapped_links:
        redirects = [name for name in wrapped.wrappers if is_open_redirect(name)]
        if redirects:
            add_finding(
                findings,
                10,
                f"Link hidden behind {redirects[0]}, real target: {wrapped.target}",
            )

    check_link_text_mismatch(email, findings)

    sender_domain = registered_domain(extract_email_domain(email.from_address))

    for bare_link in email.bare_links:
        bare_host = bare_link.split("/", 1)[0]

        # The sender's own website in a signature is normal, not a lure.
        if sender_domain and registered_domain(bare_host) == sender_domain:
            continue

        add_finding(
            findings,
            25,
            f"Link written without http(s)://, so it is not clickable or scanned: {bare_link}",
        )

    if email.copy_paste_instruction:
        add_finding(
            findings,
            15,
            "Asks the reader to copy and paste a link into the browser",
        )


def check_link_text_mismatch(email: EmailInvestigation, findings: list[Finding]) -> None:
    """Flag links whose visible text shows one domain but which go to another."""
    reported: set[tuple[str, str]] = set()

    for pair in email.link_texts:
        target = urlparse(pair.target)
        if target.scheme not in {"http", "https"}:
            continue

        shown_host = host_shown_in_text(pair.text)
        if not shown_host:
            continue

        shown = registered_domain(shown_host)
        real = registered_domain(target.hostname or "")

        if not real or shown == real or real in CLICK_TRACKING_DOMAINS:
            continue

        if (shown, real) in reported:
            continue
        reported.add((shown, real))

        add_finding(
            findings,
            25,
            f"Link text shows {shown_host} but the link goes to {target.hostname}",
        )


def host_shown_in_text(text: str) -> str:
    """Hostname a reader would see in link text, if the text looks like a link."""
    url_match = re.search(r"https?://[^\s\"'<>]+", text, re.IGNORECASE)
    if url_match:
        return (urlparse(url_match.group(0)).hostname or "").lower()

    bare = extract_bare_links(text)
    if bare:
        return bare[0].split("/", 1)[0]

    return ""


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