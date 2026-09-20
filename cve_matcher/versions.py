"""A small, dependency-free version comparator.

Real semver and PEP 440 comparison each have edge cases (build metadata,
epochs, pre-release ordering rules, ecosystem-specific quirks) that a
from-scratch implementation cannot fully cover. This module implements a
single generic comparator good enough for the common case in both
ecosystems: a dotted run of numeric segments, optionally followed by a
``-``/``+``-delimited pre-release/build tag. See the "Limitations" section
of the README for exactly what this does not handle.
"""

from __future__ import annotations

import re

_SPLIT_RE = re.compile(r"[.+]")
_NUMERIC_RE = re.compile(r"^\d+$")


def _parse(version: str) -> tuple[tuple[int, ...], str]:
    """Split a version into a numeric core tuple and a trailing pre-release tag."""
    version = version.strip()
    core = version
    pre = ""
    for sep in ("-",):
        if sep in version:
            core, _, pre = version.partition(sep)
            break

    segments: list[int] = []
    for part in _SPLIT_RE.split(core):
        if _NUMERIC_RE.match(part):
            segments.append(int(part))
        else:
            # Non-numeric segment (e.g. "1.2.3b1" from a manifest that
            # skipped a separator) - stop the numeric core here and fold
            # the remainder into the pre-release tag instead of guessing.
            pre = part if not pre else f"{part}.{pre}"
            break
    return tuple(segments), pre


def compare(a: str, b: str) -> int:
    """Return -1, 0, or 1 as ``a`` is less than, equal to, or greater than ``b``.

    A missing pre-release tag sorts *after* any present tag (release >
    pre-release), matching both semver and PEP 440 conventions.
    """
    a_core, a_pre = _parse(a)
    b_core, b_pre = _parse(b)

    length = max(len(a_core), len(b_core))
    a_padded = a_core + (0,) * (length - len(a_core))
    b_padded = b_core + (0,) * (length - len(b_core))
    if a_padded != b_padded:
        return -1 if a_padded < b_padded else 1

    if a_pre == b_pre:
        return 0
    if not a_pre:
        return 1
    if not b_pre:
        return -1
    return -1 if a_pre < b_pre else 1


def in_range(target: str, events: tuple[tuple[str, str], ...]) -> bool:
    """Evaluate an OSV-style event list against ``target``.

    ``events`` is an ordered sequence of ``(kind, version)`` pairs where
    ``kind`` is one of ``introduced`` / ``fixed`` / ``last_affected`` /
    ``limit``. ``fixed`` and ``limit`` are exclusive upper bounds, while
    ``last_affected`` is inclusive.
    """
    affected = False
    for kind, version in events:
        relation = compare(target, version)
        if kind == "introduced" and (version == "0" or relation >= 0):
            affected = True
        elif kind in ("fixed", "limit") and relation >= 0:
            affected = False
        elif kind == "last_affected" and relation > 0:
            affected = False
    return affected
