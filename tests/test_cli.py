from pathlib import Path

from cve_matcher.__main__ import main


FIXTURES = Path(__file__).parent / "fixtures"


def test_missing_osv_database_fails_closed(capsys):
    exit_code = main(
        [
            "--pip-requirements",
            str(FIXTURES / "requirements.sample.txt"),
            "--osv-db",
            str(FIXTURES / "missing"),
        ]
    )
    assert exit_code == 2
    assert "not found" in capsys.readouterr().err


def test_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("expected SystemExit from argparse version action")
    assert "cve-matcher 0.1.0" in capsys.readouterr().out
