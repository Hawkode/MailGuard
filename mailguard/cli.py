from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from mailguard.folder_scan import scan_folder
from mailguard.parser import parse_eml
from mailguard.report import print_basic_report

app = typer.Typer(
    help="MailGuard: defensive email investigation CLI.",
    no_args_is_help=True,
)

console = Console()


@app.callback()
def main():
    """
    Analyse suspicious email files safely.
    """
    pass


@app.command()
def analyze(file: Path):
    """
    Analyse a suspicious email file.
    """
    result = parse_eml(file)
    print_basic_report(result)


@app.command("scan-folder")
def scan_folder_command(folder: Path):
    """
    Analyse all email-like files in a folder.
    """
    result = scan_folder(folder)

    console.rule("[bold]MailGuard Folder Scan Summary[/bold]")
    console.print(f"[bold]Scanned:[/bold] {result.scanned}")
    console.print(f"[bold]High risk:[/bold] {result.high_risk}")
    console.print(f"[bold]Suspicious:[/bold] {result.suspicious}")
    console.print(f"[bold]Low risk:[/bold] {result.low_risk}")
    console.print(f"[bold]Skipped:[/bold] {result.skipped}")
    console.print(f"[bold]Errors:[/bold] {result.errors}")

if __name__ == "__main__":
    app()