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

    ``events`` is a sequence of ``(kind, version)`` pairs where ``kind`` is
    one of ``introduced`` / ``fixed`` / ``last_affected`` / ``limit``. This
    follows the evaluation model described by the public OSV schema: find
    the event with the greatest version that is still ``<= target``, and
    that event's kind determines whether ``target`` is affected.
    """
    applicable = [
        (kind, version)
        for kind, version in events
        if kind in ("introduced", "fixed", "last_affected")
        and compare(version, target) <= 0
    ]
    if not applicable:
        return False

    def sort_key(item: tuple[str, str]) -> tuple[int, ...]:
        return _parse(item[1])[0]

    applicable.sort(key=sort_key)
    kind, version = applicable[-1]
    if kind == "introduced":
        return True
    if kind == "fixed":
        return False
    if kind == "last_affected":
        return compare(target, version) == 0
    return False
