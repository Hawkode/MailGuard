from mailguard.parser import LinkText, parse_eml
from mailguard.scoring import assess_email, check_link_text_mismatch
from mailguard.unwrap import unwrap_url


def test_safe_links_unwrapped():
    url = (
        "https://eur02.safelinks.protection.outlook.com/?url=https%3A%2F%2F"
        "parcel-redeliver.example.web.app%2Fpay&data=05%7C02&reserved=0"
    )
    result = unwrap_url(url)
    assert result.target == "https://parcel-redeliver.example.web.app/pay"
    assert result.wrappers == ["Microsoft Safe Links"]


def test_proofpoint_v2_unwrapped():
    url = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_login&d=DwMF&c=x"
    assert unwrap_url(url).target == "https://evil.example/login"


def test_proofpoint_v3_unwrapped():
    url = "https://urldefense.com/v3/__https://evil.example/login__;!!abc123$"
    assert unwrap_url(url).target == "https://evil.example/login"


def test_barracuda_unwrapped():
    url = "https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fevil.example%2fx&c=E,1,abc"
    assert unwrap_url(url).target == "https://evil.example/x"


def test_nested_safe_links_and_google_redirect():
    inner = "https%3A%2F%2Fwww.google.com%2Furl%3Fq%3Dhttps%3A%2F%2Fevil.example%2Fpay"
    url = f"https://eur02.safelinks.protection.outlook.com/?url={inner}&data=1"
    result = unwrap_url(url)
    assert result.target == "https://evil.example/pay"
    assert result.wrappers == ["Microsoft Safe Links", "Google redirect"]


def test_plain_link_is_untouched():
    result = unwrap_url("https://portal.vendor.example/login")
    assert result.target == "https://portal.vendor.example/login"
    assert result.wrappers == []


def mismatch_messages(pairs):
    class Stub:
        link_texts = pairs

    findings = []
    check_link_text_mismatch(Stub(), findings)
    return [f.message for f in findings]


def test_link_text_mismatch_flagged():
    pairs = [LinkText("https://www.royalmail.com/track", "https://redeliver.example.web.app/pay")]
    assert mismatch_messages(pairs)


def test_same_organisation_and_tracking_and_mailto_not_flagged():
    pairs = [
        LinkText("www.vendor.co.uk", "https://shop.vendor.co.uk/offers"),
        LinkText("www.vendor.co.uk", "https://u123.ct.sendgrid.net/ls/click?upn=abc"),
        LinkText("support@vendor.co.uk", "mailto:support@vendor.co.uk"),
        LinkText("Open company portal", "https://evil.example/login"),
    ]
    assert mismatch_messages(pairs) == []


def test_parcel_lure_judged_on_real_target():
    email = parse_eml("tests/fixtures/parcel_safelinks_lure.eml")
    assessment = assess_email(email)
    messages = " ".join(f.message for f in assessment.findings)

    assert email.links == ["https://parcel-redeliver.example.web.app/pay"]
    assert "safelinks" not in messages
    assert "goes to parcel-redeliver.example.web.app" in messages
    assert "composite authentication failed (reason 001)" in messages
