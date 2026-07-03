from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from bs4 import BeautifulSoup
import re


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int


@dataclass
class EmailInvestigation:
    subject: str
    from_address: str
    reply_to: str
    return_path: str
    date: str
    message_id: str
    text_body: str
    html_body: str
    links: list[str]
    attachments: list[AttachmentInfo]


def parse_eml(file_path: str | Path) -> EmailInvestigation:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {path}")

    with path.open("rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    for part in message.walk():
        content_disposition = part.get_content_disposition()
        content_type = part.get_content_type()

        if content_disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                AttachmentInfo(
                    filename=part.get_filename() or "unknown",
                    content_type=content_type,
                    size_bytes=len(payload),
                )
            )
            continue

        if content_type == "text/plain":
            text_parts.append(part.get_content())

        if content_type == "text/html":
            html_parts.append(part.get_content())

    text_body = "\n".join(text_parts).strip()
    html_body = "\n".join(html_parts).strip()

    links = extract_links(text_body, html_body)

    return EmailInvestigation(
        subject=message.get("subject", ""),
        from_address=message.get("from", ""),
        reply_to=message.get("reply-to", ""),
        return_path=message.get("return-path", ""),
        date=message.get("date", ""),
        message_id=message.get("message-id", ""),
        text_body=text_body,
        html_body=html_body,
        links=links,
        attachments=attachments,
    )


def extract_links(text_body: str, html_body: str) -> list[str]:
    links: set[str] = set()

    for match in URL_PATTERN.findall(text_body):
        links.add(clean_url(match))

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")

        for tag in soup.find_all("a", href=True):
            links.add(clean_url(tag["href"]))

        for tag in soup.find_all("img", src=True):
            links.add(clean_url(tag["src"]))

    return sorted(links)


def clean_url(url: str) -> str:
    return url.strip().rstrip(".,);]")