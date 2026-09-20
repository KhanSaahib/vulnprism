# cve-matcher

Static hardening scanners (the kind this author's `blue-forge` repo is full
of - `depguard`, `iacguard`, `k8sguard`, `dockerguard`) catch *misconfigured*
dependencies: typosquats, unpinned versions, missing lockfiles. None of them
answer the much more direct question: **is a package version I actually ship
one with a publicly disclosed, known vulnerability?** `depguard`'s own README
says as much - its "known-compromised" table is "a small, illustrative set of
famous historical incidents, not a live threat feed" and explicitly suggests
pairing it with OSV.dev, the GitHub Advisory Database, or a commercial feed
"for real coverage." `cve-matcher` is that missing piece.

`cve-matcher` reads a CycloneDX SBOM, an npm `package-lock.json`, or a Python
`requirements.txt`, and cross-references every resolved (name, version)
against a local export of [OSV-schema](https://ossf.github.io/osv-schema/)
vulnerability records - the interchange format used by OSV.dev, the GitHub
Advisory Database, and the PyPA Advisory Database. It makes **no network
calls itself**: like `certwatch`'s CT-log export or `depguard`'s
registry-free manifest scan, you bring the OSV export file(s) (e.g. an
extracted per-ecosystem `all.zip` from OSV.dev, or a handful of saved
`api.osv.dev` responses) and `cve-matcher` matches offline.

## Why this over `depguard` alone

`depguard` catches supply-chain *hygiene* problems (typosquats, unpinned
versions, malicious install scripts) with no external data source needed.
`cve-matcher` catches the complementary case: a dependency that is perfectly
well-behaved and correctly pinned, but is a version with a CVE. Run both -
they report on different, non-overlapping risks.

## Install

No dependencies beyond the Python 3.10+ standard library.

```bash
git clone <this repo>
cd cve-matcher
python3 -m pytest tests/ -q   # optional: run the test suite
```

Or build and install it as a package (dependency-free wheel, console script
`cve-matcher`):

```bash
python -m pip install build
python -m build                          # -> dist/cve_matcher-*.whl
python -m pip install --no-deps dist/cve_matcher-*.whl
cve-matcher --help
```

## Usage

```bash
# Get an OSV export once, e.g. per-ecosystem dumps from OSV.dev:
#   curl -O https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
#   unzip all.zip -d osv_data/npm
# or save a handful of https://api.osv.dev/v1/query responses as .json files.

python3 -m cve_matcher \
  --sbom sbom.cdx.json \
  --npm-lockfile package-lock.json \
  --pip-requirements requirements.txt \
  --osv-db osv_data/ \
  --min-score 40 \
  --format markdown \
  --output cve_report.md
```

`--sbom`, `--npm-lockfile`, `--pip-requirements`, and `--osv-db` are all
repeatable and can be combined in one run. `--osv-db` accepts a file or a
directory (scanned recursively for `*.json`; each file may contain a single
OSV record, a JSON array of records, or an `{"vulns": [...]}` query-response
envelope). `--format json` produces a machine-readable, schema-versioned
report suitable for a ticketing pipeline; `--fail-on-findings` exits `1` if
any finding remains after `--min-score` filtering, for CI gating.

### Example output

```
## 1. GHSA-example-lodash (CVE-2020-8203) - lodash@4.17.19 - severity 75 (HIGH)
- Ecosystem: npm (from sbom)
- Matched via: range
- Severity basis: database_specific.severity label
- fix: upgrade to `4.17.21`
- Summary: Prototype pollution in lodash before 4.17.21
```

## How matching works

For each component, `cve-matcher` looks for an OSV record with an `affected`
entry that shares its ecosystem and (normalized) package name, then checks
either an exact `versions` list match or evaluates the record's version
`ranges` against the component's version using the algorithm the OSV schema
itself describes: walk the `introduced`/`fixed`/`last_affected` events in
increasing version order and take whichever event's version is the greatest
one still `<=` the component's version - if that event is `introduced`, the
version is affected; `fixed` or an exceeded `last_affected` means it is not.
See `cve_matcher/versions.py`.

## Severity scoring

`cve-matcher` reports severity on its own 0-100 scale, derived in priority
order: (1) a plain `database_specific.severity` label if the OSV record has
one (CRITICAL=95, HIGH=75, MEDIUM=50, LOW=20); (2) otherwise, a **heuristic
approximation** from a CVSS v3/v4 vector string's own metric values
(`cve_matcher/severity.py::vector_heuristic_score`) - explicitly *not* the
official CVSS base-score formula, since that requires the full
impact/exploitability/scope-changed calculation; (3) otherwise `UNKNOWN` at a
default of 40, so an unscored record is still visible in a report rather than
silently sorted to the bottom. Every finding's `severity_basis` field says
exactly which of the three applied - never hidden, per this project's
"evidence, not an authoritative determination" convention.

## Limitations (documented, not hidden)

- **Version comparison is a generic heuristic**, not full semver or PEP 440:
  it compares dotted numeric segments plus a single trailing pre-release tag.
  Build metadata, PEP 440 epochs, and ecosystem-specific pre-release
  ordering rules are not modeled. See `cve_matcher/versions.py`.
- **The CVSS vector heuristic is an approximation**, not an official CVSS
  base score - use it only to rank findings against each other, not as a
  substitute for a real CVSS calculator.
- **`requirements.txt` support is `==`-pins only.** A range constraint
  (`>=2.0,<3.0`) has no single resolved version to check against, so those
  lines are skipped rather than guessed at - run `pip freeze` first if you
  need exact installed versions checked.
- **No transitive dependency resolution beyond what the SBOM/lockfile
  already lists.** An SBOM generator (Syft, `cyclonedx-npm`, `cyclonedx-py`)
  is expected to have already flattened the dependency tree; `cve-matcher`
  only reads what's in the file.
- **No network access, ever** - the OSV export's freshness is entirely the
  operator's responsibility, same as `certwatch`'s CT log export in
  `blue-forge`.

## Project layout

```
cve_matcher/
  models.py           # Component / Vulnerability / Finding dataclasses
  versions.py          # dependency-free version comparator + OSV range evaluator
  severity.py           # severity scoring (label-based + CVSS-vector heuristic)
  osv_loader.py          # reads a local OSV-schema JSON export
  manifest_loader.py      # reads CycloneDX SBOM / npm lockfile / requirements.txt
  match.py                 # component <-> vulnerability matching
  report.py                 # Markdown / JSON rendering
  __main__.py                # CLI
tests/                        # pytest suite + sample OSV/SBOM/lockfile fixtures
```

## License and attribution

MIT licensed (see `LICENSE`). This tool contains no code copied from any
other project; see `NOTICE.md` for every public specification and prior-art
project this was built against, and exactly what each contributed.

## Continuous integration

`.github/workflows/ci.yml` runs `python -m pytest -q` on Python 3.10-3.13 for
every push and pull request.

Local equivalent:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```
