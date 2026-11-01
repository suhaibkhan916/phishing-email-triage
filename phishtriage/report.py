"""Render an Analysis as a Markdown triage note in the shape a SOC ticket expects."""
from __future__ import annotations

from .analyzer import Analysis, defang

ACTIONS = {
    "malicious": [
        "Block the sender domain and every URL/domain IOC listed above at the mail gateway and web proxy.",
        "Search the mailbox store for the same subject, sender and attachment hash; purge all matches.",
        "Identify recipients who clicked or opened the attachment and escalate those hosts to Tier 2 for EDR review.",
        "Reset credentials for any user who entered them on a linked page or opened the attachment.",
    ],
    "suspicious": [
        "Hold the message in quarantine pending sender verification through a second channel.",
        "Add the domain IOCs to the watchlist and re-check reputation in 24 hours.",
        "Warn the recipient not to click links or reply until verified.",
    ],
    "benign": [
        "No action required. Close the ticket as a false positive and record the sender as known-good.",
    ],
}


def render_markdown(a: Analysis) -> str:
    out = [f"# Triage note: {a.subject or a.file}", ""]
    out += [
        f"- **Sample:** `{a.file}`",
        f"- **Verdict:** **{a.verdict.upper()}** (risk score {a.score}/100)",
        f"- **From:** {a.from_display} <{defang(a.from_addr)}>",
        f"- **Reply-To:** {defang(a.reply_to) or 'none'}",
        f"- **Return-Path:** {defang(a.return_path) or 'none'}",
        "- **Authentication:** " + (", ".join(f"{k.upper()}={v}" for k, v in sorted(a.auth.items())) or "no results"),
        "- **Public hops in Received chain (oldest last):** "
        + (", ".join(f"`{defang(ip)}`" for ip in a.received_ips) or "none"),
        "",
        "## Why this verdict",
        "",
    ]
    if a.findings:
        out += ["| Points | Indicator | Detail |", "|---:|---|---|"]
        out += [f"| {f.points} | `{f.code}` | {f.detail.replace('|', '/')} |" for f in a.findings]
    else:
        out.append("No indicators fired.")

    out += ["", "## Indicators of compromise", ""]
    if a.urls:
        out += ["| URL (defanged) | Link text |", "|---|---|"]
        out += [f"| `{u.defanged}` | {u.anchor_text or '-'} |" for u in a.urls]
        out.append("")
    if a.attachments:
        out += ["| Attachment | Type | Bytes | SHA-256 |", "|---|---|---:|---|"]
        out += [f"| `{x.filename}` | {x.content_type} | {x.size} | `{x.sha256}` |" for x in a.attachments]
        out.append("")
    if not a.urls and not a.attachments:
        out += ["No URLs or attachments.", ""]

    out += ["## Recommended actions", ""]
    out += [f"{i}. {step}" for i, step in enumerate(ACTIONS[a.verdict], 1)]
    out += [
        "",
        "## MITRE ATT&CK",
        "",
        "- T1566.001 Phishing: Spearphishing Attachment" if a.attachments else "",
        "- T1566.002 Phishing: Spearphishing Link" if a.urls and a.verdict != "benign" else "",
    ]
    return "\n".join(line for line in out if line is not None).rstrip() + "\n"
