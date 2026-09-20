# Contributing

Thanks for helping improve `cve-matcher`.

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
