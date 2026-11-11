"""CLI smoke tests. They need typer and rich, so they run in CI after
'pip install -e .[test]' and are skipped where those are not installed."""
import json

import pytest

typer_testing = pytest.importorskip("typer.testing")
pytest.importorskip("rich")

from mailguard.cli import app  # noqa: E402

runner = typer_testing.CliRunner()


def test_analyze_prints_report():
    result = runner.invoke(app, ["analyze", "tests/fixtures/ms_verdict_phish.eml"])
    assert result.exit_code == 0, result.output
    assert "Microsoft verdict" in result.output
    assert "High risk" in result.output


def test_analyze_writes_json(tmp_path):
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["analyze", "tests/fixtures/parcel_safelinks_lure.eml", "--json", str(out)])
    assert result.exit_code == 0, result.output

    report = json.loads(out.read_text())
    assert report["risk"]["verdict"] == "High risk"
    assert report["wrapped_links"][0]["wrappers"] == ["Microsoft Safe Links"]
    assert "payload" not in json.dumps(report["attachments"])


def test_scan_folder():
    result = runner.invoke(app, ["scan-folder", "tests/fixtures"])
    assert result.exit_code == 0, result.output
    assert "Scanned" in result.output
