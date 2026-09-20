# Notice and attribution

`VulnPrism` is 100% original code written for this repository. It contains
no code copied from any other project. This file records every public
project, specification, or data source that informed its design, and exactly
what was drawn from each.

## OSV Schema (Open Source Vulnerability format)

- Project: https://ossf.github.io/osv-schema/ (Open Source Security
  Foundation)
- License: CC-BY-SA-4.0 (schema/spec), field names/shape used as a public
  interchange format
- What was used: only the public JSON field names and semantics documented
  by the spec (`id`, `summary`, `aliases`, `affected[].package.{ecosystem,name}`,
  `affected[].versions`, `affected[].ranges[].{type,events}`,
  `severity[].{type,score}`, `database_specific.severity`) and the publicly
  described range-evaluation model (walk sorted `introduced`/`fixed`/
  `last_affected` events to determine whether a version is inside a range).
  No schema file, validator, or code was copied. `vulnprism/osv_loader.py`
  and `vulnprism/versions.py` are original implementations against this
  public interchange format, the same way `k8sguard` elsewhere in this
  author's `blue-forge` repo reads the public Kubernetes API field names.

## OSV.dev vulnerability database

- Project: https://osv.dev (Google / Open Source Security Foundation)
- License: the OSV.dev database itself is aggregated from many upstream
  advisory sources (GHSA, PyPA Advisory Database, npm advisory data, etc.)
  each with its own license/terms; OSV.dev publishes its own data under
  CC-BY-4.0. `VulnPrism` does not ship, bundle, or redistribute any OSV.dev
  data - it only reads a local export the operator supplies themselves, the
  same "bring your own offline export" convention this author's `certwatch`
  (Certificate Transparency export) and `depguard` (manifest, no registry
  calls) tools already use. No data or code from OSV.dev is included in this
  repository.

## CycloneDX SBOM format

- Project: https://cyclonedx.org/ (OWASP)
- License: Apache-2.0 (specification)
- What was used: only the public JSON field names (`components[].name`,
  `components[].version`, `components[].purl`) needed to read an SBOM a
  third-party tool (e.g. `cyclonedx-npm`, `cyclonedx-py`, Syft) already
  produced. No schema file or code was copied.

## Package URL (purl) specification

- Project: https://github.com/package-url/purl-spec
- License: MIT
- What was used: only the public `pkg:<type>/<name>@<version>` string shape,
  to map a purl's type field (`npm`, `pypi`, `maven`, ...) to the
  corresponding OSV ecosystem name. No code was copied.

## CVSS v3.1 vector string format

- Specification: https://www.first.org/cvss/v3-1/specification-document
  (FIRST.org)
- What was used: only the public metric abbreviations (`AV`, `AC`, `PR`,
  `UI`, `C`, `I`, `A`) to build `severity.vector_heuristic_score`, which is
  explicitly **not** the official CVSS base-score formula - it is a
  documented, simplified weighted-average approximation used only to rank
  findings relative to each other. See the docstring in
  `vulnprism/severity.py` for exactly what it does and does not compute.

## Prior art consulted for the general approach (no code or data used)

- OSV-Scanner (Google, Apache-2.0) and Grype (Anchore, Apache-2.0) - the
  general idea of "match an SBOM/manifest against a vulnerability database
  offline." No code, rules, matching logic, or data from either project was
  read, copied, or ported; `VulnPrism`'s version-range algorithm, severity
  heuristic, and manifest parsers were all written from scratch against the
  public specs cited above.
