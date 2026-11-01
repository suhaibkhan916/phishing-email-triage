"""Static analysis of .eml files: headers, URLs and attachments become IOCs and a scored verdict."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".lnk", ".iso",
    ".img", ".bat", ".cmd", ".ps1", ".jar", ".docm", ".xlsm", ".pptm", ".html", ".htm",
}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}

BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "docusign": "docusign.net",
}

URGENCY_RE = re.compile(
    r"\b(urgent|immediately|within 24 hours|suspended|verify your account|limited|"
    r"action required|final notice|unusual activity|expires? today|password expir\w+)\b",
    re.I,
)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)

PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


@dataclass
class Finding:
    points: int
    code: str
    detail: str


@dataclass
class UrlIoc:
    url: str
    defanged: str
    host: str
    anchor_text: str = ""


@dataclass
class AttachmentIoc:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str


@dataclass
class Analysis:
    file: str
    subject: str
    from_display: str
    from_addr: str
    reply_to: str
    return_path: str
    auth: dict[str, str]
    received_ips: list[str]
    urls: list[UrlIoc] = field(default_factory=list)
    attachments: list[AttachmentIoc] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "benign"

    def to_dict(self) -> dict:
        return asdict(self)

    def iocs(self) -> dict[str, list[str]]:
        domains = {u.host for u in self.urls if u.host and not _is_ip(u.host)}
        sender_domain = _domain_of(self.from_addr)
        if sender_domain:
            domains.add(sender_domain)
        ips = set(self.received_ips) | {u.host for u in self.urls if _is_ip(u.host)}
        return {
            "domains": sorted(domains),
            "urls": sorted({u.url for u in self.urls}),
            "ips": sorted(ips),
            "sha256": sorted({a.sha256 for a in self.attachments}),
        }


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def defang(value: str) -> str:
    return value.replace("http", "hxxp", 1).replace(".", "[.]") if value else value


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def registered_domain(host: str) -> str:
    # Naive last-two-labels split; public-suffix aware parsing is out of scope for this tool.
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def normalize_homoglyphs(label: str) -> str:
    table = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "4": "a"})
    return label.translate(table).replace("rn", "m").replace("vv", "w")


def impersonated_brand(domain: str) -> str | None:
    """Return the brand a domain imitates, or None if it is the brand's own domain or unrelated."""
    reg = registered_domain(domain)
    label = normalize_homoglyphs(reg.split(".")[0])
    for brand, legit in BRANDS.items():
        if reg == legit:
            return None
        if brand in label:
            return brand
    return None


def _is_public_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return False
    return not any(ip in net for net in PRIVATE_NETS)


def load_eml(path: str | Path) -> EmailMessage:
    with open(path, "rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain.append(part.get_content())
        elif ctype == "text/html":
            html.append(part.get_content())
    return "\n".join(plain), "\n".join(html)


def analyze(path: str | Path) -> Analysis:
    msg = load_eml(path)
    display, addr = parseaddr(str(msg.get("From", "")))
    addr = addr.lower()
    reply_addrs = [a.lower() for _, a in getaddresses([str(msg.get("Reply-To", ""))]) if a]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()

    auth = {k.lower(): v.lower() for k, v in AUTH_RE.findall(" ".join(msg.get_all("Authentication-Results", [])))}

    received_ips: list[str] = []
    for hop in msg.get_all("Received", []):
        for ip in IPV4_RE.findall(str(hop)):
            if _is_public_ip(ip) and ip not in received_ips:
                received_ips.append(ip)

    plain, html = _bodies(msg)
    result = Analysis(
        file=Path(path).name,
        subject=str(msg.get("Subject", "")),
        from_display=display,
        from_addr=addr,
        reply_to=", ".join(reply_addrs),
        return_path=return_path,
        auth=auth,
        received_ips=received_ips,
    )

    seen: set[str] = set()
    parser = _LinkParser()
    parser.feed(html)
    for href, text in parser.links:
        if href.lower().startswith(("http://", "https://")) and href not in seen:
            seen.add(href)
            host = urlparse(href).hostname or ""
            result.urls.append(UrlIoc(href, defang(href), host, text))
    for raw in URL_RE.findall(plain + "\n" + html):
        url = raw.rstrip(".,;")
        if url not in seen:
            seen.add(url)
            result.urls.append(UrlIoc(url, defang(url), urlparse(url).hostname or ""))

    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        result.attachments.append(
            AttachmentIoc(
                filename=part.get_filename() or "(unnamed)",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                md5=hashlib.md5(payload).hexdigest(),
            )
        )

    _score(result, plain + "\n" + html)
    return result


def _score(r: Analysis, body_text: str) -> None:
    def add(points: int, code: str, detail: str) -> None:
        r.findings.append(Finding(points, code, detail))

    spf, dkim, dmarc = r.auth.get("spf"), r.auth.get("dkim"), r.auth.get("dmarc")
    if spf == "fail":
        add(20, "SPF_FAIL", "SPF failed: sending server is not authorised for the From domain.")
    elif spf == "softfail":
        add(10, "SPF_SOFTFAIL", "SPF softfail: sending server is probably not authorised.")
    elif spf in (None, "none"):
        add(5, "SPF_MISSING", "No SPF result present.")
    if dkim == "fail":
        add(20, "DKIM_FAIL", "DKIM signature failed validation.")
    elif dkim in (None, "none"):
        add(8, "DKIM_MISSING", "Message carries no DKIM signature.")
    if dmarc == "fail":
        add(20, "DMARC_FAIL", "DMARC failed: From domain did not align with SPF or DKIM.")

    from_domain = _domain_of(r.from_addr)
    rp_domain = _domain_of(r.return_path)
    if rp_domain and from_domain and registered_domain(rp_domain) != registered_domain(from_domain):
        add(10, "RETURN_PATH_MISMATCH", f"Return-Path domain {rp_domain} differs from From domain {from_domain}.")
    for rt in r.reply_to.split(", "):
        rt_domain = _domain_of(rt)
        if rt_domain and from_domain and registered_domain(rt_domain) != registered_domain(from_domain):
            add(15, "REPLY_TO_MISMATCH", f"Replies go to {rt_domain}, not the sender domain {from_domain}.")
            break

    display_lower = r.from_display.lower()
    for brand, legit in BRANDS.items():
        if brand in display_lower and registered_domain(from_domain) != legit:
            add(25, "DISPLAY_NAME_BRAND", f"Display name claims '{brand}' but mail comes from {from_domain}.")
            break

    imitated = impersonated_brand(from_domain) if from_domain else None
    if imitated:
        add(25, "LOOKALIKE_SENDER", f"Sender domain {from_domain} imitates {imitated}.")

    if URGENCY_RE.search(body_text):
        add(10, "URGENCY_LANGUAGE", "Body uses pressure language (urgency, suspension, expiry).")

    for u in r.urls:
        if _is_ip(u.host):
            add(20, "URL_IS_IP", f"Link points at a raw IP address: {u.defanged}")
        if u.url.lower().startswith("http://"):
            add(5, "URL_NOT_HTTPS", f"Unencrypted link: {u.defanged}")
        link_brand = impersonated_brand(u.host) if u.host and not _is_ip(u.host) else None
        if link_brand:
            add(25, "LOOKALIKE_URL", f"Link domain {u.host} imitates {link_brand}.")
        shown = re.search(r"(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", u.anchor_text.lower())
        if shown and u.host and registered_domain(shown.group(1)) != registered_domain(u.host):
            add(30, "ANCHOR_MISMATCH", f"Link text shows {shown.group(1)} but goes to {u.host}.")

    for a in r.attachments:
        suffixes = [s.lower() for s in Path(a.filename).suffixes]
        if suffixes and suffixes[-1] in RISKY_EXTENSIONS:
            add(30, "RISKY_ATTACHMENT", f"Executable/script attachment type: {a.filename}")
        if len(suffixes) >= 2 and suffixes[-1] in RISKY_EXTENSIONS and suffixes[-2] in DOCUMENT_EXTENSIONS:
            add(20, "DOUBLE_EXTENSION", f"Document extension masks a script/executable: {a.filename}")

    r.score = min(100, sum(f.points for f in r.findings))
    r.verdict = "malicious" if r.score >= 60 else "suspicious" if r.score >= 25 else "benign"
