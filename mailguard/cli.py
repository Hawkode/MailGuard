from __future__ import annotations

from pathlib import Path

import typer

from mailguard.parser import parse_eml
from mailguard.report import print_basic_report

app = typer.Typer(
    help="MailGuard: defensive email investigation CLI.",
    no_args_is_help=True,
)


@app.callback()
def main():
    """
    Analyse suspicious email files safely.
    """
    pass


@app.command()
def analyze(file: Path):
    """
    Analyse a suspicious .eml email file.
    """
    result = parse_eml(file)
    print_basic_report(result)


if __name__ == "__main__":
    app()