"""Severity scoring on cve-matcher's own 0-100 scale.

OSV records carry severity two different ways: a plain label
(``database_specific.severity``, e.g. GitHub Security Advisories) or a raw
CVSS vector string (``severity[].type`` == ``CVSS_V3``/``CVSS_V4``). Computing
an exact official CVSS base score requires the full impact/exploitability
formula (including the scope-changed special case), which is out of scope
here. Instead, ``vector_heuristic_score`` computes a documented
*approximation*: a weighted average of the vector's own metric values. It is
useful for ranking findings relative to each other; it is not a substitute
for the real CVSS calculator when an exact score matters.
"""

from __future__ import annotations

import re

_LABEL_SCORES = {
    "CRITICAL": 95.0,
    "HIGH": 75.0,
    "MODERATE": 50.0,
    "MEDIUM": 50.0,
    "LOW": 20.0,
}

_AV = {"N": 1.0, "A": 0.75, "L": 0.5, "P": 0.25}
_AC = {"L": 1.0, "H": 0.5}
_PR = {"N": 1.0, "L": 0.65, "H": 0.3}
_UI = {"N": 1.0, "P": 0.7, "R": 0.6, "A": 0.4}
_IMPACT = {"H": 1.0, "L": 0.5, "N": 0.0}

_VECTOR_RE = re.compile(r"(?:^|/)([A-Z]{1,2}):([A-Za-z])")

UNKNOWN_SCORE = 40.0
UNKNOWN_LABEL = "UNKNOWN"


def label_for_score(score: float) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return UNKNOWN_LABEL


def score_from_label(label: str) -> float | None:
    return _LABEL_SCORES.get(label.strip().upper())


def vector_heuristic_score(vector: str) -> float | None:
    """Approximate a 0-100 severity from a CVSS v3/v4 vector string.

    Not an official CVSS base score - see the module docstring. Returns
    ``None`` if the vector is missing the metrics this heuristic needs.
    """
    metrics = {key: value.upper() for key, value in _VECTOR_RE.findall(vector)}
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = _PR[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        # CVSS v3 uses C/I/A; v4 renamed vulnerable-system impact metrics to
        # VC/VI/VA. This is still a ranking heuristic, not official CVSS math.
        c = _IMPACT[metrics["C"] if "C" in metrics else metrics["VC"]]
        i = _IMPACT[metrics["I"] if "I" in metrics else metrics["VI"]]
        a = _IMPACT[metrics["A"] if "A" in metrics else metrics["VA"]]
    except KeyError:
        return None

    exploitability = (av + ac + pr + ui) / 4.0
    impact = (c + i + a) / 3.0
    combined = exploitability * 0.4 + impact * 0.6
    return round(combined * 100.0, 1)


def resolve_severity(
    database_specific_severity: str | None,
    severity_entries: list[dict],
) -> tuple[float, str, str]:
    """Return ``(score, label, basis)`` for an OSV vulnerability record."""
    if database_specific_severity:
        score = score_from_label(database_specific_severity)
        if score is not None:
            return score, label_for_score(score), "database_specific.severity label"

    for entry in severity_entries:
        vector = entry.get("score", "")
        if entry.get("type", "").startswith("CVSS") and vector:
            score = vector_heuristic_score(vector)
            if score is not None:
                basis = f"heuristic estimate from {entry['type']} vector (not official CVSS math)"
                return score, label_for_score(score), basis

    return UNKNOWN_SCORE, UNKNOWN_LABEL, "no usable severity field in the OSV record"
