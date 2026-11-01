# Triage note: Action required: your PayPal account has been limited

- **Sample:** `01_credential_harvest.eml`
- **Verdict:** **MALICIOUS** (risk score 100/100)
- **From:** PayPal Security <service@paypa1-secure[.]test>
- **Reply-To:** collect@mailbox-drop[.]test
- **Return-Path:** bounce@mailer-xyz[.]test
- **Authentication:** DKIM=none, DMARC=fail, SPF=fail
- **Public hops in Received chain (oldest last):** `203[.]0[.]113[.]45`

## Why this verdict

| Points | Indicator | Detail |
|---:|---|---|
| 20 | `SPF_FAIL` | SPF failed: sending server is not authorised for the From domain. |
| 8 | `DKIM_MISSING` | Message carries no DKIM signature. |
| 20 | `DMARC_FAIL` | DMARC failed: From domain did not align with SPF or DKIM. |
| 10 | `RETURN_PATH_MISMATCH` | Return-Path domain mailer-xyz.test differs from From domain paypa1-secure.test. |
| 15 | `REPLY_TO_MISMATCH` | Replies go to mailbox-drop.test, not the sender domain paypa1-secure.test. |
| 25 | `DISPLAY_NAME_BRAND` | Display name claims 'paypal' but mail comes from paypa1-secure.test. |
| 25 | `LOOKALIKE_SENDER` | Sender domain paypa1-secure.test imitates paypal. |
| 10 | `URGENCY_LANGUAGE` | Body uses pressure language (urgency, suspension, expiry). |
| 5 | `URL_NOT_HTTPS` | Unencrypted link: hxxp://paypa1-secure[.]test/login?id=8842 |
| 25 | `LOOKALIKE_URL` | Link domain paypa1-secure.test imitates paypal. |
| 30 | `ANCHOR_MISMATCH` | Link text shows www.paypal.com but goes to paypa1-secure.test. |

## Indicators of compromise

| URL (defanged) | Link text |
|---|---|
| `hxxp://paypa1-secure[.]test/login?id=8842` | https://www.paypal.com/verify |
| `hxxps://www[.]paypal[.]com/verify` | - |

## Recommended actions

1. Block the sender domain and every URL/domain IOC listed above at the mail gateway and web proxy.
2. Search the mailbox store for the same subject, sender and attachment hash; purge all matches.
3. Identify recipients who clicked or opened the attachment and escalate those hosts to Tier 2 for EDR review.
4. Reset credentials for any user who entered them on a linked page or opened the attachment.

## MITRE ATT&CK


- T1566.002 Phishing: Spearphishing Link
