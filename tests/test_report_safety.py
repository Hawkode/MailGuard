import pytest

pytest.importorskip("rich")

from mailguard.report import safe  # noqa: E402


def test_ansi_escape_and_markup_are_neutralised():
    hostile = "Invoice \x1b[2J\x1b[31m[bold red]PAID[/bold red]\x07"
    cleaned = safe(hostile)
    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert "\\[bold red]" in cleaned


def test_links_are_defanged_so_they_cannot_be_clicked():
    from mailguard.report import defang

    assert defang("https://parcel-redeliver.example.web.app/pay") == "hxxps://parcel-redeliver[.]example[.]web[.]app/pay"
    assert defang("go to http://192.0.2.9/login now") == "go to hxxp://192[.]0[.]2[.]9/login now"
    assert defang("no links here") == "no links here"
