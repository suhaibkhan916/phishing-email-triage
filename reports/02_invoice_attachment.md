# Triage note: Invoice 3381 - payment overdue

- **Sample:** `02_invoice_attachment.eml`
- **Verdict:** **MALICIOUS** (risk score 78/100)
- **From:** Accounts Payable <billing@acme-supplies[.]test>
- **Reply-To:** billing@acme-supplies[.]test
- **Return-Path:** billing@acme-supplies[.]test
- **Authentication:** DKIM=none, DMARC=none, SPF=softfail
- **Public hops in Received chain (oldest last):** `198[.]51[.]100[.]77`

## Why this verdict

| Points | Indicator | Detail |
|---:|---|---|
| 10 | `SPF_SOFTFAIL` | SPF softfail: sending server is probably not authorised. |
| 8 | `DKIM_MISSING` | Message carries no DKIM signature. |
| 10 | `URGENCY_LANGUAGE` | Body uses pressure language (urgency, suspension, expiry). |
| 30 | `RISKY_ATTACHMENT` | Executable/script attachment type: Invoice_3381.pdf.js |
| 20 | `DOUBLE_EXTENSION` | Document extension masks a script/executable: Invoice_3381.pdf.js |

## Indicators of compromise

| Attachment | Type | Bytes | SHA-256 |
|---|---|---:|---|
| `Invoice_3381.pdf.js` | application/octet-stream | 64 | `50ddcdf1f647b324928ce8259824c38c9aaff19563a784def5d3f76e50580af6` |

## Recommended actions

1. Block the sender domain and every URL/domain IOC listed above at the mail gateway and web proxy.
2. Search the mailbox store for the same subject, sender and attachment hash; purge all matches.
3. Identify recipients who clicked or opened the attachment and escalate those hosts to Tier 2 for EDR review.
4. Reset credentials for any user who entered them on a linked page or opened the attachment.

## MITRE ATT&CK

- T1566.001 Phishing: Spearphishing Attachment
