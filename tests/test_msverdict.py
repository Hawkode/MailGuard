from email import message_from_string, policy

from mailguard.msverdict import (
    describe_compauth_reason,
    parse_bcl,
    parse_compauth,
    parse_forefront_report,
    read_microsoft_verdict,
)
from mailguard.parser import parse_eml
from mailguard.scoring import assess_email


def test_forefront_fields_split():
    fields = parse_forefront_report("CIP:198.51.100.23;CTRY:NL;SCL:5;SFV:SPM;CAT:PHSH;SFTY:9.25;DIR:INB;")
    assert fields["CAT"] == "PHSH"
    assert fields["SFV"] == "SPM"
    assert fields["CIP"] == "198.51.100.23"


def test_folded_header_still_parses():
    fields = parse_forefront_report("CIP:198.51.100.23;CTRY:NL;\r\n SCL:1;SFV:NSPM;\r\n\tCAT:NONE;")
    assert fields["SFV"] == "NSPM"
    assert fields["CAT"] == "NONE"


def test_bcl_and_compauth():
    assert parse_bcl("BCL:8;ARA:1") == 8
    assert parse_bcl("ARA:1") is None
    assert parse_compauth("dmarc=fail action=quarantine header.from=x.example;compauth=fail reason=000") == ("fail", "000")
    assert describe_compauth_reason("601").startswith("Spoofs one of your own")


def test_topmost_header_wins_over_planted_copy():
    raw = (
        "X-Forefront-Antispam-Report: CIP:192.0.2.9;SFV:SPM;CAT:PHSH;\n"
        "X-Forefront-Antispam-Report: CIP:192.0.2.9;SFV:NSPM;CAT:NONE;\n"
        "From: a@b.example\n\nbody\n"
    )
    verdict = read_microsoft_verdict(message_from_string(raw, policy=policy.default))
    assert verdict.category == "PHSH"


def test_no_microsoft_headers_returns_none():
    email = parse_eml("examples/suspicious.eml")
    assert email.microsoft_verdict is None


def test_microsoft_phish_verdict_scored():
    email = parse_eml("tests/fixtures/ms_verdict_phish.eml")
    assessment = assess_email(email)
    messages = [f.message for f in assessment.findings]

    assert email.microsoft_verdict.category == "PHSH"
    assert "Microsoft verdict: Phishing (CAT:PHSH)" in messages
    assert any("composite authentication failed (reason 001)" in m for m in messages)
    assert any("First contact" in m for m in messages)
    assert assessment.verdict == "High risk"


def test_allow_list_bypass_is_reported_without_points():
    raw = (
        "X-Forefront-Antispam-Report: CIP:192.0.2.9;SFV:SKN;CAT:NONE;SCL:-1;\n"
        "From: a@b.example\nMessage-ID: <x@b.example>\n\nbody\n"
    )
    from mailguard.scoring import check_microsoft_verdict

    class Stub:
        microsoft_verdict = read_microsoft_verdict(message_from_string(raw, policy=policy.default))

    findings = []
    check_microsoft_verdict(Stub(), findings)
    assert len(findings) == 1
    assert findings[0].points == 0
    assert "mail flow (transport) rule" in findings[0].message
