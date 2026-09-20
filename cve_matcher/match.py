"""Cross-references components against a loaded OSV vulnerability set."""

from __future__ import annotations

import re
from functools import cmp_to_key

from .models import Component, Finding, Vulnerability
from .versions import compare, in_range

_PYPI_NORMALIZE_RE = re.compile(r"[-_.]+")


def _normalize_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return _PYPI_NORMALIZE_RE.sub("-", name).lower()
    return name


def find_findings(components: list[Component], vulnerabilities: list[Vulnerability]) -> list[Finding]:
    findings: list[Finding] = []
    for component in components:
        component_name = _normalize_name(component.name, component.ecosystem)
        for vuln in vulnerabilities:
            for package in vuln.affected:
                if component.ecosystem and package.ecosystem != component.ecosystem:
                    continue
                if _normalize_name(package.name, package.ecosystem) != component_name:
                    continue

                if component.version in package.versions:
                    findings.append(Finding(component, vuln, matched_via="exact-version"))
                    break

                matched_range = False
                for version_range in package.ranges:
                    if in_range(component.version, version_range.events):
                        findings.append(Finding(component, vuln, matched_via="range"))
                        matched_range = True
                        break
                if matched_range:
                    break
    return findings


def nearest_fix(finding: Finding) -> str | None:
    """The lowest known fixed version that is still above the component's version, if any."""
    candidates = [
        v for v in finding.vulnerability.fixed_versions if compare(v, finding.component.version) > 0
    ]
    if not candidates:
        return None
    return min(candidates, key=cmp_to_key(compare))
