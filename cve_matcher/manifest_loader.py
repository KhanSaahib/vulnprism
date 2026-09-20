"""Extracts (name, version, ecosystem) components from an SBOM or manifest.

Supported inputs: a CycloneDX JSON SBOM's ``components`` array, an npm
``package-lock.json`` (v1's nested ``dependencies``, or v2/v3's flat
``packages`` map), and a Python ``requirements.txt`` with ``==`` pins.
Anything without a concrete, resolved version (a version range in
requirements.txt, a component with no ``version`` field) is skipped rather
than guessed at - matching cannot happen without a specific version.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Component

_PURL_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "composer": "Packagist",
    "gem": "RubyGems",
}

_PURL_RE = re.compile(r"^pkg:([^/]+)/(.+)@([^?@]+)")
_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)\s*(?:;.*)?$")


def _purl_to_ecosystem(purl: str) -> str:
    match = _PURL_RE.match(purl)
    if not match:
        return ""
    return _PURL_ECOSYSTEM.get(match.group(1).lower(), match.group(1))


def load_cyclonedx_sbom(path: str, default_ecosystem: str = "") -> list[Component]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    components: list[Component] = []
    for entry in data.get("components", []):
        name = entry.get("name")
        version = entry.get("version")
        if not name or not version:
            continue
        purl = entry.get("purl")
        ecosystem = _purl_to_ecosystem(purl) if purl else default_ecosystem
        components.append(
            Component(name=name, version=version, ecosystem=ecosystem, source="sbom", purl=purl)
        )
    return components


def _npm_name_from_path(pkg_path: str) -> str | None:
    if not pkg_path:
        return None
    parts = pkg_path.split("node_modules/")
    return parts[-1] if parts[-1] else None


def _walk_lockfile_v1_deps(deps: dict) -> list[Component]:
    components: list[Component] = []
    for name, info in deps.items():
        version = info.get("version")
        if version:
            components.append(
                Component(name=name, version=version, ecosystem="npm", source="npm-lockfile")
            )
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            components.extend(_walk_lockfile_v1_deps(nested))
    return components


def load_npm_lockfile(path: str) -> list[Component]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data.get("packages"), dict):
        components: list[Component] = []
        for pkg_path, info in data["packages"].items():
            if pkg_path == "":
                continue
            name = info.get("name") or _npm_name_from_path(pkg_path)
            version = info.get("version")
            if not name or not version:
                continue
            components.append(
                Component(name=name, version=version, ecosystem="npm", source="npm-lockfile")
            )
        return components
    if isinstance(data.get("dependencies"), dict):
        return _walk_lockfile_v1_deps(data["dependencies"])
    return []


def load_pip_requirements(path: str) -> list[Component]:
    components: list[Component] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _REQ_LINE_RE.match(stripped)
        if not match:
            continue
        name, version = match.groups()
        components.append(
            Component(name=name, version=version, ecosystem="PyPI", source="pip-requirements")
        )
    return components
