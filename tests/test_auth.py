import ipaddress

from mailguard.auth import parse_authentication_results
from mailguard.headers import classify_ip
from mailguard.parser import parse_eml
from mailguard.scoring import assess_email


def test_relaxed_alignment_with_subdomains():
    auth = parse_authentication_results(
        ["spf=pass smtp.mailfrom=bounce.mail.vendor.co.uk; dkim=none; dmarc=none header.from=vendor.co.uk"]
    )
    assert auth.spf_aligned("vendor.co.uk")
    assert auth.aligned("vendor.co.uk")


def test_dkim_from_mailing_service_domain_is_not_aligned():
    auth = parse_authentication_results(
        ["spf=pass smtp.mailfrom=em.mailer.example; dkim=pass header.d=mailer.example; dmarc=none"]
    )
    assert not auth.aligned("vendor.example")


def test_only_topmost_authentication_results_is_used():
    auth = parse_authentication_results(
        [
            "mx.contoso.example; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail header.from=microsoft.com",
            "mx.contoso.example; spf=pass; dkim=pass; dmarc=pass",
        ]
    )
    assert auth.dmarc == "fail"
    assert auth.spf == "fail"


def test_newsletter_through_mailing_service_is_low_risk():
    assessment = assess_email(parse_eml("tests/fixtures/newsletter_esp.eml"))
    messages = " ".join(f.message for f in assessment.findings)

    assert assessment.verdict == "Low risk"
    assert "Envelope sender" not in messages  # DMARC passed, so Return-Path is irrelevant
    assert "accountant" not in messages
    keyword_findings = [f for f in assessment.findings if f.message.startswith("Suspicious keyword")]
    assert len(keyword_findings) <= 3


def test_failed_authentication_not_counted_twice_when_compauth_present():
    assessment = assess_email(parse_eml("tests/fixtures/ms_verdict_phish.eml"))
    messages = [f.message for f in assessment.findings]

    assert not any(m.startswith("DKIM") for m in messages)
    assert not any(m.startswith("SPF") for m in messages)


def test_documentation_ips_are_not_labelled_private():
    assert classify_ip(ipaddress.ip_address("203.0.113.50")) == "documentation"
    assert classify_ip(ipaddress.ip_address("10.0.0.5")) == "private"
    assert classify_ip(ipaddress.ip_address("51.141.5.228")) == "public"
