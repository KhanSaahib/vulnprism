from cve_matcher.severity import resolve_severity, vector_heuristic_score


def test_label_based_severity():
    score, label, basis = resolve_severity("HIGH", [])
    assert score == 75.0
    assert label == "HIGH"
    assert "label" in basis


def test_vector_heuristic_high_impact_network_vector():
    score = vector_heuristic_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None
    assert score > 90


def test_vector_heuristic_returns_none_for_incomplete_vector():
    assert vector_heuristic_score("CVSS:3.1/AV:N/AC:L") is None


def test_unknown_when_no_severity_data():
    score, label, basis = resolve_severity(None, [])
    assert label == "UNKNOWN"
    assert score == 40.0
