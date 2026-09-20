from pathlib import Path

from cve_matcher.manifest_loader import load_cyclonedx_sbom, load_pip_requirements
from cve_matcher.match import find_findings, nearest_fix
from cve_matcher.osv_loader import load_osv_db
from cve_matcher.report import to_json, to_markdown

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
