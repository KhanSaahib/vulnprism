"""CLI entry point: python -m cve_matcher ..."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .manifest_loader import load_cyclonedx_sbom, load_npm_lockfile, load_pip_requirements
from .match import find_findings
from .models import Component
from .osv_loader import load_osv_db
from .report import to_json, to_markdown


def _collect_components(args: argparse.Namespace) -> list[Component]:
    components: list[Component] = []
    for path in args.sbom:
        components.extend(load_cyclonedx_sbom(path, default_ecosystem=args.ecosystem or ""))
    for path in args.npm_lockfile:
        components.extend(load_npm_lockfile(path))
    for path in args.pip_requirements:
        components.extend(load_pip_requirements(path))
    return components


def _score(value: str) -> float:
    score = float(value)
    if not 0 <= score <= 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return score


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve-matcher",
        description="Offline CVE/vulnerability matching against a CycloneDX SBOM or npm/pip manifest, "
        "using a local OSV-schema vulnerability export. No network access.",
    )
    parser.add_argument("--sbom", action="append", type=Path, default=[], help="Path to a CycloneDX JSON SBOM.")
    parser.add_argument(
        "--npm-lockfile", action="append", type=Path, default=[], help="Path to an npm package-lock.json."
    )
    parser.add_argument(
        "--pip-requirements",
        action="append",
        type=Path,
        default=[],
        help="Path to a requirements.txt with ==-pinned dependencies.",
    )
    parser.add_argument(
        "--ecosystem",
        default="",
        help="Fallback OSV ecosystem name (e.g. npm, PyPI) for SBOM components with no purl.",
    )
    parser.add_argument(
        "--osv-db",
        action="append",
        type=Path,
        default=[],
        required=True,
        help="Path to a directory (searched recursively) or file of local OSV-schema JSON records.",
    )
    parser.add_argument("--min-score", type=_score, default=0.0, help="Drop findings below this score (0-100).")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", type=Path, help="Write the report here instead of stdout.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 if any finding remains after filtering, for CI gating.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        components = _collect_components(args)
        vulnerabilities = load_osv_db(args.osv_db)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"error: could not load input: {exc}", file=sys.stderr)
        return 2
    if not components:
        print("error: no components found (pass --sbom, --npm-lockfile, or --pip-requirements)", file=sys.stderr)
        return 2
    unknown_ecosystem = [component for component in components if not component.ecosystem]
    if unknown_ecosystem:
        print(
            f"warning: skipped {len(unknown_ecosystem)} component(s) with no ecosystem; "
            "use --ecosystem for SBOMs without package URLs",
            file=sys.stderr,
        )
        components = [component for component in components if component.ecosystem]
    if not components:
        print("error: no components have a known ecosystem", file=sys.stderr)
        return 2
    if not vulnerabilities:
        print("error: no valid vulnerability records found in the OSV database", file=sys.stderr)
        return 2

    findings = find_findings(components, vulnerabilities)
    findings = [f for f in findings if f.score >= args.min_score]

    report = to_json(findings) if args.format == "json" else to_markdown(findings)
    if args.output:
        try:
            args.output.write_text(report, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 2
    else:
        print(report)

    if args.fail_on_findings and findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
