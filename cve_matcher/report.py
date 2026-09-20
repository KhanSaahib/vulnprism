"""Markdown / JSON rendering for a list of Findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .match import nearest_fix
from .models import Finding

SCHEMA_VERSION = 1


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.score, reverse=True)


def to_json(findings: list[Finding]) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [
            {
                "id": f.vulnerability.id,
                "aliases": list(f.vulnerability.aliases),
                "summary": f.vulnerability.summary,
                "component": f.component.name,
                "version": f.component.version,
                "ecosystem": f.component.ecosystem,
                "source": f.component.source,
                "matched_via": f.matched_via,
                "severity_score": f.vulnerability.severity_score,
                "severity_label": f.vulnerability.severity_label,
                "severity_basis": f.vulnerability.severity_basis,
                "fixed_version": nearest_fix(f),
            }
            for f in _sorted(findings)
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(findings: list[Finding]) -> str:
    if not findings:
        return "# cve-matcher report\n\nNo known vulnerabilities matched.\n"

    lines = [
        "# cve-matcher report",
        "",
        f"{len(findings)} finding(s) across {len({f.component.name for f in findings})} component(s).",
        "",
    ]
    for i, f in enumerate(_sorted(findings), start=1):
        fix = nearest_fix(f)
        fix_line = f"fix: upgrade to `{fix}`" if fix else "fix: no fixed version known"
        aliases = f" ({', '.join(f.vulnerability.aliases)})" if f.vulnerability.aliases else ""
        lines.append(
            f"## {i}. {f.vulnerability.id}{aliases} - {f.component.name}@{f.component.version} "
            f"- severity {f.vulnerability.severity_score:.0f} ({f.vulnerability.severity_label})"
        )
        lines.append(f"- Ecosystem: {f.component.ecosystem or 'unknown'} (from {f.component.source})")
        lines.append(f"- Matched via: {f.matched_via}")
        lines.append(f"- Severity basis: {f.vulnerability.severity_basis}")
        lines.append(f"- {fix_line}")
        if f.vulnerability.summary:
            lines.append(f"- Summary: {f.vulnerability.summary}")
        lines.append("")
    return "\n".join(lines)
