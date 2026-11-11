import pytest

pytest.importorskip("rich")

from mailguard.report import safe  # noqa: E402


def test_ansi_escape_and_markup_are_neutralised():
    hostile = "Invoice \x1b[2J\x1b[31m[bold red]PAID[/bold red]\x07"
    cleaned = safe(hostile)
    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert "\\[bold red]" in cleaned
