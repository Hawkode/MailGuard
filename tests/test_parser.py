from mailguard.parser import parse_eml


def test_parse_sample_email():
    result = parse_eml("examples/suspicious.eml")

    assert "invoice payment update" in result.subject.lower()
    assert "cesare" in result.from_address.lower()
    assert result.reply_to != ""
    assert len(result.links) >= 1
    assert len(result.attachments) == 1
    assert result.attachments[0].filename == "invoice.pdf"