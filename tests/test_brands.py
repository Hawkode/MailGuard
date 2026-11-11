from mailguard.brands import address_in_display_name, claimed_brand
from mailguard.parser import parse_eml
from mailguard.scoring import assess_email


def test_brand_from_unrelated_domain_is_flagged():
    assert claimed_brand("Royal Mail", "rm-delivery-uk.example") == "Royal Mail"
    assert claimed_brand("HMRC Tax Refund", "hmrc-refunds.example") == "HMRC"
    assert claimed_brand("Microsoft 365 Security", "m365-alerts.example") == "Microsoft"


def test_brand_from_its_own_domain_is_not_flagged():
    assert claimed_brand("Royal Mail", "email.royalmail.com") == ""
    assert claimed_brand("HMRC", "notifications.service.gov.uk") == ""
    assert claimed_brand("Microsoft account team", "accountprotection.microsoft.com") == ""
    assert claimed_brand("Amazon Web Services", "aws.amazonaws.com") == ""


def test_ordinary_business_names_are_not_brands():
    for name in ("Nationwide Plumbing Ltd", "Lloyds Pharmacy", "Apple Tree Nursery", "Hermes Paris", "Jo Bloggs"):
        assert claimed_brand(name, "smallbiz.example") == "", name


def test_address_in_display_name():
    assert address_in_display_name("support@paypal.com", "evil.example") == "support@paypal.com"
    assert address_in_display_name("jo@vendor.example", "vendor.example") == ""


def test_parcel_lure_flags_brand():
    assessment = assess_email(parse_eml("tests/fixtures/parcel_safelinks_lure.eml"))
    assert any("claims Royal Mail" in f.message for f in assessment.findings)
    assert assessment.verdict == "High risk"
