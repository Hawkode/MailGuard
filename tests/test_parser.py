from mailguard.parser import parse_eml
from mailguard.scoring import assess_email


def test_parse_sample_email():
    result = parse_eml("examples/suspicious.eml")

    assert "invoice payment update" in result.subject.lower()
    assert "cesare" in result.from_address.lower()
    assert result.reply_to != ""
    assert len(result.links) >= 1
    assert len(result.attachments) == 1
    assert result.attachments[0].filename == "invoice.pdf"
    assert len(result.attachments[0].sha256) == 64


def test_sample_email_has_high_risk_score():
    result = parse_eml("examples/suspicious.eml")
    assessment = assess_email(result)

    assert assessment.score >= 66
    assert assessment.verdict == "High risk"
    assert len(assessment.findings) >= 3