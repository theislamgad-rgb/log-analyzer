"""Render findings as a readable text report or as JSON."""
import json
from collections import Counter
from typing import List

from .detectors import SEVERITY_ORDER, Finding


def summary_counts(findings: List[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def render_text(findings: List[Finding], stats: dict) -> str:
    lines = ["=" * 78, "LOG ANALYZER REPORT", "=" * 78]
    lines.append(f"Auth events parsed: {stats['auth_events']} (skipped lines: {stats['auth_skipped']})")
    lines.append(f"Web events parsed:  {stats['web_events']} (skipped lines: {stats['web_skipped']})")
    counts = summary_counts(findings)
    parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]]
    lines.append(f"Findings: {len(findings)}" + (f"  ({', '.join(parts)})" if parts else ""))
    lines.append("-" * 78)
    if not findings:
        lines.append("No suspicious activity detected with the current thresholds.")
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule}  src={f.ip}  count={f.count}")
        lines.append(f"           {f.first_seen}  ->  {f.last_seen}")
        lines.append(f"           {f.detail}")
    lines.append("=" * 78)
    return "\n".join(lines)


def render_json(findings: List[Finding], stats: dict) -> str:
    return json.dumps(
        {"stats": stats, "summary": dict(summary_counts(findings)),
         "findings": [f.to_dict() for f in findings]},
        indent=2)
