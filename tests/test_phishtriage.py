from pathlib import Path

import pytest

from phishtriage.analyzer import analyze, defang, impersonated_brand, registered_domain
from phishtriage.enrich import vt_url_id
from phishtriage.report import render_markdown

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def codes(a):
    return {f.code for f in a.findings}


@pytest.mark.parametrize(
    "name,verdict",
    [
        ("01_credential_harvest.eml", "malicious"),
        ("02_invoice_attachment.eml", "malicious"),
        ("03_password_expiry.eml", "suspicious"),
        ("04_benign_newsletter.eml", "benign"),
    ],
)
def test_verdicts(name, verdict):
    assert analyze(SAMPLES / name).verdict == verdict


def test_credential_harvest_indicators():
    a = analyze(SAMPLES / "01_credential_harvest.eml")
    assert {"SPF_FAIL", "DMARC_FAIL", "ANCHOR_MISMATCH", "LOOKALIKE_URL", "DISPLAY_NAME_BRAND", "REPLY_TO_MISMATCH"} <= codes(a)
    assert a.received_ips == ["203.0.113.45"]
    assert a.iocs()["domains"] == ["paypa1-secure.test"] or "paypa1-secure.test" in a.iocs()["domains"]


def test_attachment_is_hashed_and_flagged():
    a = analyze(SAMPLES / "02_invoice_attachment.eml")
    assert {"RISKY_ATTACHMENT", "DOUBLE_EXTENSION"} <= codes(a)
    assert len(a.attachments[0].sha256) == 64
    assert a.attachments[0].filename == "Invoice_3381.pdf.js"


def test_benign_sample_has_no_false_positives():
    a = analyze(SAMPLES / "04_benign_newsletter.eml")
    assert a.score == 0 and not a.findings


def test_private_hop_is_not_an_ioc():
    a = analyze(SAMPLES / "01_credential_harvest.eml")
    assert "10.0.0.5" not in a.received_ips


def test_defang():
    assert defang("http://evil.test/a.php") == "hxxp://evil[.]test/a[.]php"


def test_lookalike_detection():
    assert impersonated_brand("paypa1-secure.test") == "paypal"
    assert impersonated_brand("rnicrosoft-login.test") == "microsoft"
    assert impersonated_brand("paypal.com") is None
    assert impersonated_brand("example.com") is None


def test_registered_domain():
    assert registered_domain("mail-out.paypa1-secure.test") == "paypa1-secure.test"


def test_virustotal_url_id_has_no_padding():
    assert "=" not in vt_url_id("http://a.test/")


def test_report_contains_verdict_and_defanged_ioc():
    md = render_markdown(analyze(SAMPLES / "01_credential_harvest.eml"))
    assert "MALICIOUS" in md and "hxxp://paypa1-secure[.]test" in md
