from cve_matcher.versions import compare, in_range


def test_compare_basic_numeric():
    assert compare("1.2.3", "1.2.4") < 0
    assert compare("1.10.0", "1.9.0") > 0
    assert compare("2.0.0", "2.0.0") == 0


def test_compare_prerelease_sorts_before_release():
    assert compare("1.0.0-rc1", "1.0.0") < 0
    assert compare("1.0.0", "1.0.0-rc1") > 0


def test_compare_ignores_semver_build_metadata():
    assert compare("1.2.3+linux.x86", "1.2.3") == 0
    assert compare("1.2.3+build.2", "1.2.3+build.1") == 0


def test_fixed_boundary_includes_build_metadata_variant():
    events = (("introduced", "0"), ("fixed", "1.2.3"))
    assert in_range("1.2.3+vendor.1", events) is False


def test_prerelease_numeric_identifiers_use_numeric_order():
    assert compare("1.0.0-rc2", "1.0.0-rc10") < 0
    assert compare("1.0.0-alpha.1", "1.0.0-alpha.beta") < 0


def test_in_range_introduced_zero_and_fixed():
    events = (("introduced", "0"), ("fixed", "4.17.21"))
    assert in_range("4.17.19", events) is True
    assert in_range("4.17.21", events) is False
    assert in_range("4.18.0", events) is False


def test_in_range_before_introduced_is_not_affected():
    events = (("introduced", "3.1.0"), ("fixed", "3.1.13"))
    assert in_range("3.0.9", events) is False
    assert in_range("3.1.5", events) is True
    assert in_range("3.1.13", events) is False


def test_in_range_last_affected_is_inclusive():
    events = (("introduced", "0"), ("last_affected", "1.2.0"))
    assert in_range("1.2.0", events) is True
    assert in_range("1.2.1", events) is False


def test_in_range_limit_is_exclusive():
    events = (("introduced", "1.0.0"), ("limit", "2.0.0"))
    assert in_range("1.9.9", events) is True
    assert in_range("2.0.0", events) is False
    assert in_range("2.1.0", events) is False
