from __future__ import annotations

import re

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mailguard.parser import EmailInvestigation
from mailguard.scoring import assess_email
from mailguard.msverdict import describe_compauth_reason

console = Console()

# C0/C1 control characters and the escape character. Email headers, file
# names and links are attacker-controlled: an ANSI escape sequence in a
# subject line could recolour, hide or rewrite what the analyst sees.
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(value) -> str:
    """Make attacker-controlled text safe to print: no control codes, no rich markup."""
    return escape(CONTROL_CHARACTERS.sub("?", str(value)))


def print_microsoft_verdict(result: EmailInvestigation) -> None:
    verdict = result.microsoft_verdict
    console.print()

    if verdict is None:
        console.print(
            "[bold]Microsoft verdict:[/bold] none found "
            "(not delivered through Microsoft 365, or the headers were not included)"
        )
        return

    table = Table(title="Microsoft verdict (Exchange Online Protection)")
    table.add_column("Field")
    table.add_column("Value")
    table.add_column("Meaning")

    table.add_row("CAT", safe(verdict.category or "-"), safe(verdict.category_name or "-"))
    table.add_row("SFV", safe(verdict.sfv or "-"), safe(verdict.sfv_meaning or "-"))
    table.add_row(
        "compauth",
        f"{verdict.compauth or '-'} {verdict.compauth_reason}".strip(),
        describe_compauth_reason(verdict.compauth_reason) or "-",
    )
    table.add_row("SFTY", safe(verdict.sfty or "-"), safe(verdict.sfty_meaning or "-"))
    table.add_row("SCL", safe(verdict.scl or "-"), "Context only: does not decide the action in Microsoft 365")
    table.add_row("BCL", "-" if verdict.bcl is None else str(verdict.bcl), "Bulk complaint level, 0 to 9")
    table.add_row("CIP / CTRY", safe(f"{verdict.connecting_ip or '-'} / {verdict.country or '-'}"), "Connecting IP and its country")

    console.print(table)


def print_basic_report(result: EmailInvestigation) -> None:
    assessment = assess_email(result)

    console.rule("[bold]MailGuard Investigation Report[/bold]")

    console.print(f"[bold]Risk score:[/bold] {assessment.score}/100")
    console.print(f"[bold]Verdict:[/bold] {assessment.verdict}")

    print_microsoft_verdict(result)

    console.print()
    console.print(f"[bold]Subject:[/bold] {safe(result.subject or 'N/A')}")
    console.print(f"[bold]From:[/bold] {safe(result.from_address or 'N/A')}")
    console.print(f"[bold]Reply-To:[/bold] {safe(result.reply_to or 'N/A')}")
    console.print(f"[bold]Return-Path:[/bold] {safe(result.return_path or 'N/A')}")
    console.print(f"[bold]Date:[/bold] {safe(result.date or 'N/A')}")
    console.print(f"[bold]Message-ID:[/bold] {safe(result.message_id or 'N/A')}")
    console.print()
    console.print(f"[bold]Received header IPs:[/bold] {len(result.received_ips)}")

    if result.received_ips:
        ip_table = Table(title="Received Header IPs")
        ip_table.add_column("IP address")
        ip_table.add_column("Scope")

        for received_ip in result.received_ips:
            ip_table.add_row(received_ip.address, received_ip.scope)

        console.print(ip_table)

    console.print()
    console.print("[bold]Findings:[/bold]")

    if assessment.findings:
        for finding in assessment.findings:
            console.print(f"- (+{finding.points}) {safe(finding.message)}")
    else:
        console.print("- No suspicious indicators found")

    console.print()
    console.print(f"[bold]Links found:[/bold] {len(result.links)}")

    if result.links:
        link_table = Table(title="Extracted Links")
        link_table.add_column("#", justify="right")
        link_table.add_column("URL")

        for index, link in enumerate(result.links, start=1):
            link_table.add_row(str(index), safe(link))

        console.print(link_table)

    if result.wrapped_links:
        console.print()
        console.print(f"[bold]Unwrapped links:[/bold] {len(result.wrapped_links)}")
        for wrapped in result.wrapped_links:
            console.print(f"- {' > '.join(wrapped.wrappers)} > {safe(wrapped.target)}")

    if result.bare_links:
        console.print()
        console.print(f"[bold]Links without http(s)://:[/bold] {len(result.bare_links)}")
        for bare_link in result.bare_links:
            console.print(f"- {safe(bare_link)}")

    console.print()
    console.print(f"[bold]Attachments found:[/bold] {len(result.attachments)}")

    if result.attachments:
        attachment_table = Table(title="Attachments")
        attachment_table.add_column("Filename")
        attachment_table.add_column("Content type")
        attachment_table.add_column("Size", justify="right")
        attachment_table.add_column("SHA256")

        for attachment in result.attachments:
            attachment_table.add_row(
                safe(attachment.filename),
                safe(attachment.content_type),
                f"{attachment.size_bytes} bytes",
                attachment.sha256,
            )

        console.print(attachment_table)