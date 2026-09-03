"""CLI tests. Nothing here touches the network."""

import json
from unittest.mock import patch

import pytest

from certinator.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FOUND, main


def run(argv, capsys):
    code = main(argv)
    return code, capsys.readouterr()


def test_check_scores_names_offline(capsys):
    code, out = run(["check", "--brand", "paypal", "--own", "paypal.com",
                     "--no-color", "paypa1.com"], capsys)
    assert code == EXIT_FOUND
    assert "paypa1.com" in out.out


def test_check_finds_nothing_in_legitimate_names(capsys):
    code, _ = run(["check", "--brand", "paypal", "--own", "paypal.com",
                   "--no-color", "paypal.com", "www.paypal.com"], capsys)
    assert code == EXIT_CLEAN


def test_json_output_is_parseable(capsys):
    code, out = run(["check", "--brand", "paypal", "--own", "paypal.com",
                     "--json", "paypa1.com"], capsys)
    data = json.loads(out.out)
    assert data["matches"][0]["name"] == "paypa1.com"
    assert data["brands"] == ["paypal"]


def test_weak_findings_are_off_by_default(capsys):
    """A brand inside a longer name is somebody's own infrastructure far more
    often than it is an attack."""
    code, _ = run(["check", "--brand", "paypal", "--own", "paypal.com",
                   "--no-color", "paypalace-restaurant.com"], capsys)
    assert code == EXIT_CLEAN

    code, out = run(["check", "--brand", "paypal", "--own", "paypal.com",
                     "--all", "--no-color", "paypalace-restaurant.com"], capsys)
    assert code == EXIT_FOUND
    assert "paypalace-restaurant.com" in out.out


def test_a_brand_is_required(capsys):
    with pytest.raises(SystemExit) as info:
        main(["check", "example.com"])
    assert info.value.code == 2


def test_a_short_brand_is_refused_with_a_reason(capsys):
    code, out = run(["check", "--brand", "abc", "example.com"], capsys)
    assert code == EXIT_ERROR
    assert "too short" in out.err


@pytest.mark.parametrize("argv", [
    ["check", "--brand", "paypal", "--min-score", "2", "x.com"],
    ["check", "--brand", "paypal", "--min-score", "-1", "x.com"],
    ["check", "--brand", "paypal", "--top", "0", "x.com"],
])
def test_out_of_range_options_are_rejected(argv):
    with pytest.raises(SystemExit) as info:
        main(argv)
    assert info.value.code == 2


def test_top_limits_and_says_so(capsys):
    names = ["paypa1.com", "paypal.xyz", "paypall.com", "paypl.com"]
    code, out = run(["check", "--brand", "paypal", "--own", "paypal.com",
                     "--no-color", "--top", "2", *names], capsys)
    assert "showing 2 of" in out.out


def test_no_arguments_from_a_script_prints_help_rather_than_prompting(capsys):
    """A prompt in a pipeline hangs forever."""
    with patch("certinator.cli.interactive", return_value=False):
        code, out = run([], capsys)
    assert code == EXIT_ERROR
    assert "usage" in out.out.lower()


def test_a_network_failure_is_reported_not_raised(capsys):
    with patch("certinator.cli.discover", side_effect=OSError("no route")):
        code, out = run(["recent", "--brand", "paypal", "--own", "paypal.com"],
                        capsys)
    assert code == EXIT_ERROR
    assert "network error" in out.err


def test_no_usable_logs_is_reported(capsys):
    with patch("certinator.cli.discover", return_value=[]):
        code, out = run(["logs"], capsys)
    assert code == EXIT_ERROR
    assert "no usable transparency logs" in out.err


def test_homograph_of_an_owned_domain_reaches_the_output(capsys):
    """The end to end version of the bug that mattered most."""
    code, out = run(["check", "--brand", "paypal", "--own", "paypal.com",
                     "--no-color", "рaypal.com"], capsys)
    assert code == EXIT_FOUND
    assert "CRITICAL" in out.out
    assert "homograph" in out.out
