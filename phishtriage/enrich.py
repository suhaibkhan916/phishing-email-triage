"""Optional reputation lookups against VirusTotal and AlienVault OTX.

Needs API keys in the VT_API_KEY / OTX_API_KEY environment variables. Nothing here runs
unless the CLI is called with --enrich, and keys are never written to disk or output.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request

from .analyzer import Analysis

VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _get(url: str, header: str, key: str) -> dict:
    req = urllib.request.Request(url, headers={header: key, "User-Agent": "phishtriage/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        return {"error": f"HTTP {err.code}"}
    except urllib.error.URLError as err:
        return {"error": str(err.reason)}


def _vt_stats(payload: dict) -> str:
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    if not stats:
        return payload.get("error", "not found")
    return f"{stats.get('malicious', 0)} malicious / {stats.get('suspicious', 0)} suspicious / {stats.get('harmless', 0)} harmless"


def enrich(a: Analysis) -> dict[str, dict[str, str]]:
    vt_key, otx_key = os.environ.get("VT_API_KEY"), os.environ.get("OTX_API_KEY")
    if not (vt_key or otx_key):
        raise SystemExit("Set VT_API_KEY and/or OTX_API_KEY to use --enrich.")
    iocs = a.iocs()
    results: dict[str, dict[str, str]] = {}
    for sha in iocs["sha256"]:
        if vt_key:
            results[sha] = {"virustotal": _vt_stats(_get(f"{VT_BASE}/files/{sha}", "x-apikey", vt_key))}
    for domain in iocs["domains"]:
        row = results.setdefault(domain, {})
        if vt_key:
            row["virustotal"] = _vt_stats(_get(f"{VT_BASE}/domains/{domain}", "x-apikey", vt_key))
        if otx_key:
            pulses = _get(f"{OTX_BASE}/indicators/domain/{domain}/general", "X-OTX-API-KEY", otx_key)
            row["otx"] = f"{pulses.get('pulse_info', {}).get('count', 0)} pulses" if "error" not in pulses else pulses["error"]
    for ip in iocs["ips"]:
        row = results.setdefault(ip, {})
        if vt_key:
            row["virustotal"] = _vt_stats(_get(f"{VT_BASE}/ip_addresses/{ip}", "x-apikey", vt_key))
    return results
