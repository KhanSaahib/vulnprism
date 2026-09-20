# Contributing

Thanks for helping improve `VulnPrism`.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
For usage questions, read [SUPPORT.md](SUPPORT.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

Correctness takes priority over coverage. Matching changes should include
fixtures for affected, fixed, and boundary versions. Do not add online lookups
or bundle third-party vulnerability data. Document any ecosystem-specific
version behavior rather than presenting a heuristic as authoritative.

## Pull requests

- Keep each pull request focused and explain the user-facing impact.
- Add fixtures and tests for affected, fixed, and boundary versions.
- Update the README and `[Unreleased]` changelog for user-visible changes.
- Run `python -m pytest -q` and `python -m build` before requesting review.
- Do not include private SBOMs, package inventories, or vulnerability exports.

Maintainers may request changes when evidence is incomplete, behavior is not
deterministic, or a contribution expands the project's stated scope.
