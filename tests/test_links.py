from mailguard.links import (
    extract_bare_links,
    has_copy_paste_instruction,
    registered_domain,
)
from mailguard.parser import parse_eml
from mailguard.scoring import assess_email


def test_bare_link_found_without_scheme():
    text = "copy and paste this into your browser: orderdocs-48213.uc.r.appspot.com/view?id=9."
    assert extract_bare_links(text) == ["orderdocs-48213.uc.r.appspot.com/view?id=9"]


def test_full_urls_emails_and_file_names_are_not_bare_links():
    text = (
        "Go to https://portal.example.com/login, email support@helpdesk.example.com, "
        "open invoice.pdf or logo.png, e.g. version 2.5.1"
    )
    assert extract_bare_links(text) == []


def test_registered_domain_handles_uk_second_level():
    assert registered_domain("mail.vendor.co.uk") == "vendor.co.uk"
    assert registered_domain("x.y.appspot.com") == "appspot.com"


def test_copy_paste_instruction():
    assert has_copy_paste_instruction("If the link doesn't open, paste it into Chrome")
    assert not has_copy_paste_instruction("Please review the attached schedule")


def test_compromised_supplier_lure_is_no_longer_low_risk():
    email = parse_eml("tests/fixtures/bare_link_lure.eml")
    assessment = assess_email(email)
    messages = " ".join(f.message for f in assessment.findings)

    assert email.bare_links == ["orderdocs-48213.uc.r.appspot.com", "www.supplier.example"]
    assert "orderdocs-48213.uc.r.appspot.com" in messages
    assert "www.supplier.example" not in messages  # sender's own site is ignored
    assert email.copy_paste_instruction
    assert assessment.verdict != "Low risk"
