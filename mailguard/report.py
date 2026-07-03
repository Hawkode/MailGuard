from __future__ import annotations

from rich.console import Console
from rich.table import Table

from mailguard.parser import EmailInvestigation

console = Console()


def print_basic_report(result: EmailInvestigation) -> None:
    console.rule("[bold]MailGuard Investigation Report[/bold]")

    console.print(f"[bold]Subject:[/bold] {result.subject or 'N/A'}")
    console.print(f"[bold]From:[/bold] {result.from_address or 'N/A'}")
    console.print(f"[bold]Reply-To:[/bold] {result.reply_to or 'N/A'}")
    console.print(f"[bold]Return-Path:[/bold] {result.return_path or 'N/A'}")
    console.print(f"[bold]Date:[/bold] {result.date or 'N/A'}")
    console.print(f"[bold]Message-ID:[/bold] {result.message_id or 'N/A'}")

    console.print()
    console.print(f"[bold]Links found:[/bold] {len(result.links)}")

    if result.links:
        link_table = Table(title="Extracted Links")
        link_table.add_column("#", justify="right")
        link_table.add_column("URL")

        for index, link in enumerate(result.links, start=1):
            link_table.add_row(str(index), link)

        console.print(link_table)

    console.print()
    console.print(f"[bold]Attachments found:[/bold] {len(result.attachments)}")

    if result.attachments:
        attachment_table = Table(title="Attachments")
        attachment_table.add_column("Filename")
        attachment_table.add_column("Content type")
        attachment_table.add_column("Size", justify="right")

        for attachment in result.attachments:
            attachment_table.add_row(
                attachment.filename,
                attachment.content_type,
                f"{attachment.size_bytes} bytes",
            )

        console.print(attachment_table)