"""Menu tests. It is the first thing a person sees and the one part that can hang."""

from unittest.mock import patch

import pytest

from certinator.menu import ENTRIES, banner, run


def test_banner_box_is_square():
    lines = banner("certinator").split("\n")
    assert len({len(line) for line in lines}) == 1
    assert "CERTINATOR" in lines[1] and "LyfieldCreationsOS" in lines[1]


@pytest.mark.parametrize("title", ["certi", "certinator", "a-much-longer-name"])
def test_banner_adapts_to_the_title(title):
    assert len({len(line) for line in banner(title).split("\n")}) == 1


@pytest.mark.parametrize("answer", ["7", "q", "Q", ""])
def test_every_way_of_quitting(answer, capsys):
    with patch("builtins.input", side_effect=[answer]):
        assert run("certinator", lambda *_: None) == 0
    assert "Done. See you next time." in capsys.readouterr().out


@pytest.mark.parametrize("interrupt", [EOFError, KeyboardInterrupt])
def test_closing_the_terminal_exits_cleanly(interrupt, capsys):
    with patch("builtins.input", side_effect=interrupt):
        assert run("certinator", lambda *_: None) == 0
    assert "Done" in capsys.readouterr().out


def test_bad_input_reprompts(capsys):
    with patch("builtins.input", side_effect=["banana", "0", "99", "q"]):
        run("certinator", lambda *_: None)
    assert capsys.readouterr().out.count("Please type a number from 1 to 7") == 3


def test_choices_reach_dispatch_and_return_to_the_menu():
    seen = []
    with patch("builtins.input", side_effect=["1", "5", "q"]):
        run("certinator", lambda n, e: seen.append((n, e[0])))
    assert seen == [(1, "Watch"), (5, "Logs")]


def test_no_trailing_whitespace(capsys):
    with patch("builtins.input", side_effect=["q"]):
        run("certinator", lambda *_: None)
    for line in capsys.readouterr().out.split("\n"):
        assert line == line.rstrip()


def test_every_entry_has_a_blurb_except_quit():
    for name, blurb in ENTRIES[:-1]:
        assert blurb, f"{name} has no description"
    assert ENTRIES[-1] == ("Quit", "")
