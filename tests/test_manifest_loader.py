from pathlib import Path

from vulnprism.manifest_loader import (
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


def test_load_pip_requirements_accepts_extras_markers_and_comments(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text(
        'requests[socks]==2.31.0 ; python_version >= "3.10" # pinned\n',
        encoding="utf-8",
    )
    components = load_pip_requirements(str(path))
    assert [(component.name, component.version) for component in components] == [
        ("requests", "2.31.0")
    ]


def test_manifest_loaders_reject_non_object_roots(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    for loader in (load_cyclonedx_sbom, load_npm_lockfile):
        try:
            loader(str(bad))
        except ValueError as exc:
            assert "root must be an object" in str(exc)
        else:
            raise AssertionError("expected malformed manifest to be rejected")
