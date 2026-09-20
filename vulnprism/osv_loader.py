"""Loads a local export of OSV-schema vulnerability records.

VulnPrism never calls the OSV.dev API itself - the operator brings an
export (e.g. an extracted ``all.zip`` per-ecosystem dump, or a handful of
records saved from ``https://api.osv.dev/v1/query`` responses), the same
"bring your own offline export" convention blue-forge uses for certwatch's
CT log export and depguard's registry-free manifest scan.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import AffectedPackage, Vulnerability, VersionRange
from .severity import resolve_severity


def _parse_range(range_obj: dict) -> VersionRange:
    events = tuple(
        (kind, str(version))
        for event in range_obj.get("events", [])
        for kind, version in event.items()
        if kind in ("introduced", "fixed", "last_affected", "limit")
    )
    return VersionRange(range_type=range_obj.get("type", "ECOSYSTEM"), events=events)


def _range_fixed_versions(ranges: tuple[VersionRange, ...]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            version
            for version_range in ranges
            for kind, version in version_range.events
            if kind == "fixed"
        )
    )


def _parse_affected(record: dict) -> tuple[AffectedPackage, ...]:
    affected: list[AffectedPackage] = []
    for entry in record.get("affected", []):
        package = entry.get("package", {})
        name = package.get("name")
        ecosystem = package.get("ecosystem", "")
        if not name:
            continue
        versions = tuple(str(v) for v in entry.get("versions", []))
        ranges = tuple(_parse_range(r) for r in entry.get("ranges", []))
        affected.append(
            AffectedPackage(
                ecosystem=ecosystem,
                name=name,
                versions=versions,
                ranges=ranges,
                fixed_versions=_range_fixed_versions(ranges),
            )
        )
    return tuple(affected)


def _fixed_versions(affected: tuple[AffectedPackage, ...]) -> tuple[str, ...]:
    fixed: list[str] = []
    for package in affected:
        for r in package.ranges:
            for kind, version in r.events:
                if kind == "fixed":
                    fixed.append(version)
    return tuple(dict.fromkeys(fixed))


def parse_record(record: dict) -> Vulnerability | None:
    vuln_id = record.get("id")
    if not vuln_id:
        return None
    affected = _parse_affected(record)
    score, label, basis = resolve_severity(
        record.get("database_specific", {}).get("severity"),
        record.get("severity", []),
    )
    return Vulnerability(
        id=vuln_id,
        summary=record.get("summary", record.get("details", ""))[:300],
        aliases=tuple(record.get("aliases", [])),
        severity_score=score,
        severity_label=label,
        severity_basis=basis,
        affected=affected,
        fixed_versions=_fixed_versions(affected),
    )


def _iter_records(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise ValueError(f"could not read OSV JSON {path}: {exc}") from exc
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict) and isinstance(data.get("vulns"), list):
        return [r for r in data["vulns"] if isinstance(r, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def load_osv_db(paths: list[str | Path]) -> list[Vulnerability]:
    """Load every OSV JSON record found under the given files/directories."""
    vulnerabilities: list[Vulnerability] = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            raise FileNotFoundError(f"OSV database path not found: {p}")
        files = sorted(p.rglob("*.json")) if p.is_dir() else [p]
        if not files:
            raise ValueError(f"no JSON files found under OSV database path: {p}")
        for file_path in files:
            for record in _iter_records(file_path):
                try:
                    vuln = parse_record(record)
                except (AttributeError, TypeError, ValueError) as exc:
                    raise ValueError(f"invalid OSV record in {file_path}: {exc}") from exc
                if vuln is not None:
                    vulnerabilities.append(vuln)
    return vulnerabilities
