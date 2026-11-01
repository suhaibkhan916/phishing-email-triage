"""Generate the synthetic sample emails in samples/.

Everything here is fabricated for training: domains use the reserved .test TLD (RFC 2606),
IPs come from the documentation ranges (RFC 5737), and the "malicious" attachment is a
harmless text file with a script extension. Nothing here contacts or impersonates a real host.
"""
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
DATE = "Mon, 03 Nov 2025 09:14:22 +0000"


def base(subject: str, sender: str, to: str, msgid: str) -> EmailMessage:
    m = EmailMessage()
    m["From"] = sender
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = DATE
    m["Message-ID"] = msgid
    return m


def hops(m: EmailMessage, origin_ip: str, origin_host: str) -> None:
    m["Received"] = f"from mx-edge.victim-corp.test ([10.0.0.5]) by mailbox.victim-corp.test with LMTP; {DATE}"
    m["Received"] = (
        f"from {origin_host} (unknown [{origin_ip}]) by mx-edge.victim-corp.test with ESMTP; {DATE}"
    )


def credential_harvest() -> EmailMessage:
    m = base(
        "Action required: your PayPal account has been limited",
        '"PayPal Security" <service@paypa1-secure.test>',
        "j.rivera@victim-corp.test",
        "<8842.cred@paypa1-secure.test>",
    )
    m["Return-Path"] = "<bounce@mailer-xyz.test>"
    m["Reply-To"] = "collect@mailbox-drop.test"
    m["Authentication-Results"] = "mx-edge.victim-corp.test; spf=fail; dkim=none; dmarc=fail"
    hops(m, "203.0.113.45", "mail-out.paypa1-secure.test")
    m.set_content(
        "Your account has been limited. Verify within 24 hours: http://paypa1-secure.test/login?id=8842\n"
    )
    m.add_alternative(
        '<html><body><p>We noticed unusual activity. Your account is <b>suspended</b> until you '
        'verify within 24 hours.</p><p><a href="http://paypa1-secure.test/login?id=8842">'
        "https://www.paypal.com/verify</a></p></body></html>",
        subtype="html",
    )
    return m


def invoice_attachment() -> EmailMessage:
    m = base(
        "Invoice 3381 - payment overdue",
        '"Accounts Payable" <billing@acme-supplies.test>',
        "ap@victim-corp.test",
        "<3381.inv@acme-supplies.test>",
    )
    m["Return-Path"] = "<billing@acme-supplies.test>"
    m["Reply-To"] = "billing@acme-supplies.test"
    m["Authentication-Results"] = "mx-edge.victim-corp.test; spf=softfail; dkim=none; dmarc=none"
    hops(m, "198.51.100.77", "relay7.acme-supplies.test")
    m.set_content("Final notice: invoice 3381 is overdue. Open the attached invoice immediately.\n")
    m.add_attachment(
        b"// synthetic training sample - harmless text file, not a script\n",
        maintype="application",
        subtype="octet-stream",
        filename="Invoice_3381.pdf.js",
    )
    return m


def password_expiry() -> EmailMessage:
    m = base(
        "Your password expires today",
        '"IT Helpdesk" <helpdesk@yourcompany-it.test>',
        "j.rivera@victim-corp.test",
        "<pw.1177@yourcompany-it.test>",
    )
    m["Return-Path"] = "<helpdesk@yourcompany-it.test>"
    m["Reply-To"] = "reset@helpdesk-portal.test"
    m["Authentication-Results"] = "mx-edge.victim-corp.test; spf=pass; dkim=none; dmarc=none"
    hops(m, "198.51.100.12", "smtp.yourcompany-it.test")
    m.set_content("Your password expires today. Keep your access: http://helpdesk-portal.test/reset\n")
    return m


def newsletter() -> EmailMessage:
    m = base(
        "October product update",
        '"Example Weekly" <newsletter@example.com>',
        "j.rivera@victim-corp.test",
        "<oct.update@example.com>",
    )
    m["Return-Path"] = "<newsletter@example.com>"
    m["Authentication-Results"] = "mx-edge.victim-corp.test; spf=pass; dkim=pass; dmarc=pass"
    hops(m, "192.0.2.25", "mail.example.com")
    m.set_content("Read this month's update: https://example.com/blog/october\n")
    m.add_alternative(
        '<html><body><p>This month in review.</p><p><a href="https://example.com/blog/october">'
        "https://example.com/blog/october</a></p></body></html>",
        subtype="html",
    )
    return m


SAMPLES = {
    "01_credential_harvest.eml": credential_harvest,
    "02_invoice_attachment.eml": invoice_attachment,
    "03_password_expiry.eml": password_expiry,
    "04_benign_newsletter.eml": newsletter,
}

if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    for name, build in SAMPLES.items():
        (OUT / name).write_bytes(build().as_bytes())
        print(f"wrote samples/{name}")
