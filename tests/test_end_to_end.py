from pathlib import Path

from vulnprism.manifest_loader import load_cyclonedx_sbom, load_pip_requirements
from vulnprism.match import find_findings, nearest_fix
from vulnprism.models import AffectedPackage, Component, VersionRange, Vulnerability
from vulnprism.osv_loader import load_osv_db
from vulnprism.report import to_json, to_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def _load_db():
    return load_osv_db([str(FIXTURES / "osv_sample")])


def test_sbom_matches_vulnerable_and_skips_fixed_version():
    components = load_cyclonedx_sbom(str(FIXTURES / "sbom_sample.cdx.json"))
    findings = find_findings(components, _load_db())

    matched = {(f.component.name, f.component.version, f.vulnerability.id) for f in findings}
    assert ("lodash", "4.17.19", "GHSA-example-lodash") in matched
    assert ("left-pad", "1.3.0", "GHSA-example-exact") in matched
    # 4.17.21 is the fixed version - must not be flagged.
    assert ("lodash", "4.17.21", "GHSA-example-lodash") not in matched


def test_requirements_txt_matches_case_insensitive_pypi_name():
    components = load_pip_requirements(str(FIXTURES / "requirements.sample.txt"))
    findings = find_findings(components, _load_db())
    matched_ids = {f.vulnerability.id for f in findings}
    assert "PYSEC-example-django" in matched_ids


def test_nearest_fix_reports_lowest_safe_version():
    components = load_cyclonedx_sbom(str(FIXTURES / "sbom_sample.cdx.json"))
    findings = find_findings(components, _load_db())
    lodash_finding = next(f for f in findings if f.vulnerability.id == "GHSA-example-lodash")
    assert nearest_fix(lodash_finding) == "4.17.21"


def test_reports_render_without_error():
    components = load_cyclonedx_sbom(str(FIXTURES / "sbom_sample.cdx.json"))
    findings = find_findings(components, _load_db())
    assert "GHSA-example-lodash" in to_markdown(findings)
    assert "GHSA-example-lodash" in to_json(findings)


def test_empty_findings_render_clean_report():
    assert "No known vulnerabilities" in to_markdown([])


def test_unknown_ecosystem_does_not_cross_match_registry():
    component = Component("shared-name", "1.0.0", "", "sbom")
    vulnerability = Vulnerability(
        id="TEST-1",
        summary="",
        aliases=(),
        severity_score=50,
        severity_label="MEDIUM",
        severity_basis="test",
        affected=(AffectedPackage("npm", "shared-name", versions=("1.0.0",)),),
    )
    assert find_findings([component], [vulnerability]) == []


def test_git_ranges_are_not_compared_as_package_versions():
    component = Component("pkg", "2.0.0", "npm", "sbom")
    vulnerability = Vulnerability(
        id="TEST-2",
        summary="",
        aliases=(),
        severity_score=50,
        severity_label="MEDIUM",
        severity_basis="test",
        affected=(
            AffectedPackage(
                "npm",
                "pkg",
                ranges=(VersionRange("GIT", (("introduced", "deadbeef"),)),),
            ),
        ),
    )
    assert find_findings([component], [vulnerability]) == []


def test_nearest_fix_is_scoped_to_matched_package():
    component = Component("pkg", "1.5.0", "npm", "sbom")
    vulnerability = Vulnerability(
        id="TEST-3",
        summary="",
        aliases=(),
        severity_score=50,
        severity_label="MEDIUM",
        severity_basis="test",
        affected=(
            AffectedPackage(
                "npm",
                "pkg",
                ranges=(VersionRange("SEMVER", (("introduced", "0"), ("fixed", "2.0.0"))),),
                fixed_versions=("2.0.0",),
            ),
            AffectedPackage(
                "npm",
                "other",
                ranges=(VersionRange("SEMVER", (("introduced", "0"), ("fixed", "1.6.0"))),),
                fixed_versions=("1.6.0",),
            ),
        ),
        fixed_versions=("2.0.0", "1.6.0"),
    )
    finding = find_findings([component], [vulnerability])[0]
    assert nearest_fix(finding) == "2.0.0"
