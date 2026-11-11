import io
import zipfile
from email.message import EmailMessage

from mailguard.attachments import assess_attachment, mentions_missing_attachment
from mailguard.parser import parse_eml
from mailguard.scoring import assess_email


def make_zip(names, encrypted=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"test")
    data = bytearray(buffer.getvalue())
    if encrypted:
        # zipfile cannot write encrypted archives, so set the encryption
        # flag (bit 0) in the local and central directory headers by hand.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (index := data.find(signature, start)) != -1:
                data[index + offset] |= 0x1
                start = index + 4
    return bytes(data)


def messages(filename, payload=b"", inline=False):
    return [r.message for r in assess_attachment(filename, payload, inline)]


def points(filename, payload=b"", inline=False):
    return sum(r.points for r in assess_attachment(filename, payload, inline))


def test_html_and_svg_attachments_are_risky():
    assert points("Remittance.htm") >= 35
    assert points("Bonus_Schedule.svg") >= 35


def test_inline_svg_scores_lower_than_attached_svg():
    assert points("logo.svg", inline=True) < points("logo.svg")


def test_double_extension_flagged():
    assert any("Double extension" in m for m in messages("Invoice.pdf.html"))


def test_right_to_left_override_flagged():
    name = "Invoice_‮fdp.exe"
    assert any("right-to-left" in m for m in messages(name))


def test_pdf_that_is_really_html_or_exe():
    assert any("content is html" in m for m in messages("Statement.pdf", b"<!DOCTYPE html><html>"))
    assert any("content is executable" in m for m in messages("Statement.pdf", b"MZ\x90\x00"))


def test_real_office_file_is_not_flagged_as_zip():
    assert messages("Report.docx", b"PK\x03\x04rest") == []


def test_ordinary_files_have_no_findings():
    assert messages("Invoice.pdf", b"%PDF-1.7") == []
    assert messages("logo.png", b"\x89PNG", inline=True) == []


def test_zip_with_risky_inner_file():
    payload = make_zip(["Invoice_2026.pdf.lnk", "readme.txt"])
    found = messages("Docs.zip", payload)
    assert any("contains a risky file: Invoice_2026.pdf.lnk" in m for m in found)


def test_password_protected_zip():
    payload = make_zip(["statement.pdf"], encrypted=True)
    assert any("Password-protected" in m for m in messages("Docs.zip", payload))


def test_mentions_missing_attachment():
    assert mentions_missing_attachment("Hi, please see the attached document.", has_real_attachment=False)
    assert not mentions_missing_attachment("Hi, please see the attached document.", has_real_attachment=True)
    assert not mentions_missing_attachment("Thanks for the update.", has_real_attachment=False)


def test_inline_logo_is_listed_and_link_lure_scores_higher(tmp_path):
    email = parse_eml("tests/fixtures/bare_link_lure.eml")
    assessment = assess_email(email)

    assert [a.filename for a in email.attachments] == ["logo.png"]
    assert email.attachments[0].inline
    assert any("nothing is attached" in f.message for f in assessment.findings)


def test_full_email_with_risky_attachments(tmp_path):
    message = EmailMessage()
    message["From"] = "HR Team <hr@payroll-portal.example>"
    message["To"] = "staff@contoso.example"
    message["Subject"] = "Christmas bonus schedule 2026"
    message["Message-ID"] = "<bonus-001@payroll-portal.example>"
    message["Authentication-Results"] = "spf=pass smtp.mailfrom=payroll-portal.example; dkim=pass header.d=payroll-portal.example; dmarc=pass header.from=payroll-portal.example"
    message.set_content("Please review the attached bonus schedule.")
    message.add_attachment(b"<svg onload=1></svg>", maintype="image", subtype="svg+xml", filename="Bonus_Schedule.svg")
    message.add_attachment(make_zip(["Bonus.pdf.lnk"]), maintype="application", subtype="zip", filename="Docs.zip")
    path = tmp_path / "bonus.eml"
    path.write_bytes(bytes(message))

    assessment = assess_email(parse_eml(path))
    assert assessment.verdict == "High risk"
