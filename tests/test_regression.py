"""Expected verdict for every fixture.

If a scoring change moves one of these, the test fails and the change has
to be deliberate: update the expectation in the same commit and say why.
"""
import pytest

from mailguard.parser import parse_eml
from mailguard.scoring import assess_email

EXPECTED = [
    # file, verdict, why it matters
    ("examples/suspicious.eml", "High risk", "spoofed sender, DMARC fail, Reply-To elsewhere"),
    ("tests/fixtures/bare_link_lure.eml", "Suspicious", "compromised supplier: auth passes, plain-text link"),
    ("tests/fixtures/parcel_safelinks_lure.eml", "High risk", "Royal Mail lure behind Safe Links"),
    ("tests/fixtures/ms_verdict_phish.eml", "High risk", "Microsoft already said CAT:PHSH"),
    ("tests/fixtures/forged_auth_header.eml", "Suspicious", "planted pass header below the real fail"),
    ("tests/fixtures/newsletter_esp.eml", "Low risk", "genuine newsletter through a mailing service"),
    ("tests/fixtures/clean_supplier.eml", "Low risk", "normal supplier email with website in signature"),
]


@pytest.mark.parametrize("path, verdict, reason", EXPECTED, ids=[e[0].split("/")[-1] for e in EXPECTED])
def test_fixture_verdict(path, verdict, reason):
    assessment = assess_email(parse_eml(path))
    assert assessment.verdict == verdict, f"{reason}: scored {assessment.score}"


def test_clean_supplier_has_no_findings():
    assert assess_email(parse_eml("tests/fixtures/clean_supplier.eml")).findings == []
