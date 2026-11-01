# phishing-email-triage

A small command-line tool that does what a SOC Tier 1 analyst does with a reported phishing email: read the headers, pull out the indicators of compromise (IOCs), score the message, and write a triage note someone else can act on.

It takes `.eml` files and produces:

- a verdict (`malicious` / `suspicious` / `benign`) with a 0-100 risk score and the reasons behind it
- defanged URLs, sender and relay IPs, and SHA-256/MD5 hashes of attachments
- a Markdown triage note per message (see [`reports/`](reports))
- optional VirusTotal and AlienVault OTX lookups for each IOC

Standard library only, so there is nothing to install to run it.

## Run it

```bash
python scripts/make_samples.py                      # regenerate the sample emails
python -m phishtriage "samples/*.eml" --report-dir reports
python -m phishtriage samples/02_invoice_attachment.eml --json
```

Tests (13) need `pytest`:

```bash
pip install -r requirements-dev.txt
pytest
```

Reputation lookups run only when asked, and need your own API keys in the environment:

```bash
export VT_API_KEY=...   # VirusTotal
export OTX_API_KEY=...  # AlienVault OTX
python -m phishtriage samples/01_credential_harvest.eml --enrich
```

## What the samples show

Real output of `python -m phishtriage "samples/*.eml"`:

```
FILE                              VERDICT     SCORE  TOP INDICATORS
01_credential_harvest.eml         malicious     100  ANCHOR_MISMATCH, DISPLAY_NAME_BRAND, LOOKALIKE_SENDER
02_invoice_attachment.eml         malicious      78  RISKY_ATTACHMENT, DOUBLE_EXTENSION, SPF_SOFTFAIL
03_password_expiry.eml            suspicious     38  REPLY_TO_MISMATCH, URGENCY_LANGUAGE, DKIM_MISSING
04_benign_newsletter.eml          benign          0  -
```

| Sample | Scenario | What gives it away |
|---|---|---|
| 01 | Credential harvest posing as PayPal | Link text says `paypal.com`, href goes to `paypa1-secure.test`; SPF and DMARC fail; replies go to a third domain |
| 02 | Overdue-invoice lure | `Invoice_3381.pdf.js` is a script hiding behind a document extension; SPF softfail |
| 03 | Fake IT password-expiry notice | Reply-To differs from sender, urgency wording, no DKIM; not conclusive alone, so it stays `suspicious` |
| 04 | Genuine newsletter | SPF, DKIM and DMARC pass, links match the sender; scores 0 (a false-positive check) |

## How scoring works

Each indicator adds points; the total is capped at 100. 60+ is `malicious`, 25-59 is `suspicious`, below 25 is `benign`. The indicators are in [`phishtriage/analyzer.py`](phishtriage/analyzer.py):

| Area | Indicators |
|---|---|
| Authentication | SPF fail/softfail/missing, DKIM fail/missing, DMARC fail |
| Sender identity | Return-Path or Reply-To domain differs from From; display name claims a brand the domain doesn't own; lookalike domains (`paypa1`, `rnicrosoft`) |
| Links | Link text shows one domain but the href goes to another; raw-IP URLs; plain HTTP; lookalike link domains |
| Content | Urgency and account-suspension wording |
| Attachments | Script/executable/macro extensions; double extensions such as `.pdf.js` |

Mapped to MITRE ATT&CK: T1566.001 (spearphishing attachment) and T1566.002 (spearphishing link).

## About the sample data

The samples are **synthetic**, produced by [`scripts/make_samples.py`](scripts/make_samples.py). Domains use the reserved `.test` TLD, relay IPs come from the RFC 5737 documentation ranges, and the "malicious" attachment is a harmless text file with a `.js` extension. No real malware, brand mail or live infrastructure is involved. To test against real-world samples, run the tool on `.eml` files from your own reported-phishing mailbox, in an isolated VM.

## Limitations

- Scoring is heuristic and hand-weighted, not a trained classifier. Expect false positives on legitimate bulk mail that fails authentication.
- Registered-domain parsing takes the last two labels, so multi-part suffixes like `.co.uk` are not handled correctly.
- It analyses statically. It does not detonate attachments or follow redirects.
- Authentication results come from the `Authentication-Results` header added by your own gateway; the tool does not re-verify SPF/DKIM itself.

## Layout

```
phishtriage/   analyzer (parsing + scoring), report (Markdown), enrich (VT/OTX), CLI
samples/       four synthetic .eml files
reports/       triage notes generated from the samples
scripts/       sample generator
tests/         pytest suite
```

## License

MIT
