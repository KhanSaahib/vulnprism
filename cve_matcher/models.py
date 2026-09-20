"""Data model shared by the OSV loader, manifest loader, matcher and reporter."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Component:
    """One package/version pulled from an SBOM or lockfile/manifest."""

    name: str
    version: str
    ecosystem: str  # "npm", "PyPI", or "" if unknown
    source: str  # "sbom", "npm-lockfile", "pip-requirements"
    purl: str | None = None


@dataclass(frozen=True)
class VersionRange:
    range_type: str  # "SEMVER" or "ECOSYSTEM" (per the OSV schema)
    events: tuple[tuple[str, str], ...]  # ((event_kind, version), ...)


@dataclass(frozen=True)
class AffectedPackage:
    ecosystem: str
    name: str
    versions: tuple[str, ...] = field(default_factory=tuple)
    ranges: tuple[VersionRange, ...] = field(default_factory=tuple)
    fixed_versions: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Vulnerability:
    """One record from a local OSV-schema vulnerability export."""

    id: str
    summary: str
    aliases: tuple[str, ...]
    severity_score: float  # 0-100, our own normalized scale (see report.py docs)
    severity_label: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
    severity_basis: str  # how severity_score was derived, for transparency
    affected: tuple[AffectedPackage, ...]
    fixed_versions: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Finding:
    component: Component
    vulnerability: Vulnerability
    matched_via: str  # "exact-version" or "range"
    fixed_versions: tuple[str, ...] = field(default_factory=tuple)

    @property
    def score(self) -> float:
        return self.vulnerability.severity_score
