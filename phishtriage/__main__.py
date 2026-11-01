from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

from .analyzer import analyze
from .enrich import enrich
from .report import render_markdown


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phishtriage", description="Triage suspicious .eml files.")
    p.add_argument("emails", nargs="+", type=Path, help=".eml files to analyse")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON instead of a table")
    p.add_argument("--report-dir", type=Path, help="write one Markdown triage note per email here")
    p.add_argument("--enrich", action="store_true", help="look IOCs up on VirusTotal/OTX (needs API keys)")
    args = p.parse_args(argv)

    paths: list[Path] = []
    for item in args.emails:
        matches = sorted(glob.glob(str(item)))
        paths.extend(Path(m) for m in matches) if matches else p.error(f"no such file: {item}")
    analyses = [analyze(path) for path in paths]

    if args.report_dir:
        args.report_dir.mkdir(parents=True, exist_ok=True)
        for a in analyses:
            (args.report_dir / f"{Path(a.file).stem}.md").write_text(render_markdown(a), encoding="utf-8")

    if args.json:
        payload = [{**a.to_dict(), "iocs": a.iocs()} for a in analyses]
        if args.enrich:
            for a, item in zip(analyses, payload):
                item["enrichment"] = enrich(a)
        json.dump(payload, sys.stdout, indent=2)
        print()
    else:
        print(f"{'FILE':<34}{'VERDICT':<12}{'SCORE':>5}  TOP INDICATORS")
        for a in analyses:
            top = ", ".join(f.code for f in sorted(a.findings, key=lambda f: -f.points)[:3]) or "-"
            print(f"{a.file:<34}{a.verdict:<12}{a.score:>5}  {top}")
            if args.enrich:
                for ioc, rows in enrich(a).items():
                    print(f"    {ioc}: " + "; ".join(f"{k}={v}" for k, v in rows.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
