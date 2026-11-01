# Triage note: Your password expires today

- **Sample:** `03_password_expiry.eml`
- **Verdict:** **SUSPICIOUS** (risk score 38/100)
- **From:** IT Helpdesk <helpdesk@yourcompany-it[.]test>
- **Reply-To:** reset@helpdesk-portal[.]test
- **Return-Path:** helpdesk@yourcompany-it[.]test
- **Authentication:** DKIM=none, DMARC=none, SPF=pass
- **Public hops in Received chain (oldest last):** `198[.]51[.]100[.]12`

## Why this verdict

| Points | Indicator | Detail |
|---:|---|---|
| 8 | `DKIM_MISSING` | Message carries no DKIM signature. |
| 15 | `REPLY_TO_MISMATCH` | Replies go to helpdesk-portal.test, not the sender domain yourcompany-it.test. |
| 10 | `URGENCY_LANGUAGE` | Body uses pressure language (urgency, suspension, expiry). |
| 5 | `URL_NOT_HTTPS` | Unencrypted link: hxxp://helpdesk-portal[.]test/reset |

## Indicators of compromise

| URL (defanged) | Link text |
|---|---|
| `hxxp://helpdesk-portal[.]test/reset` | - |

## Recommended actions

1. Hold the message in quarantine pending sender verification through a second channel.
2. Add the domain IOCs to the watchlist and re-check reputation in 24 hours.
3. Warn the recipient not to click links or reply until verified.

## MITRE ATT&CK


- T1566.002 Phishing: Spearphishing Link
