from pathlib import Path

from cve_matcher.manifest_loader import (
    load_cyclonedx_sbom,
    load_npm_lockfile,
    load_pip_requirements,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_cyclonedx_sbom():
    components = load_cyclonedx_sbom(str(FIXTURES / "sbom_sample.cdx.json"))
    names_versions = {(c.name, c.version, c.ecosystem) for c in components}
    assert ("lodash", "4.17.19", "npm") in names_versions
    assert ("requests", "2.31.0", "PyPI") in names_versions


def test_load_npm_lockfile_v3():
    components = load_npm_lockfile(str(FIXTURES / "package-lock.sample.json"))
    names_versions = {(c.name, c.version) for c in components}
    assert ("lodash", "4.17.19") in names_versions
    assert ("left-pad", "1.3.0") in names_versions
    assert all(c.ecosystem == "npm" for c in components)


def test_load_pip_requirements_skips_unpinned():
    components = load_pip_requirements(str(FIXTURES / "requirements.sample.txt"))
    names = {c.name for c in components}
    assert "Django" in names
    assert "requests" in names
    assert "flask" not in names  # unpinned (>=), skipped
