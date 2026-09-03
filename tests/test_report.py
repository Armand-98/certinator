"""Report tests: what a person is told, and what they are not silently not told."""

import datetime
import json

import pytest

from certinator.report import (CRITICAL, HIGH, LOW, MEDIUM, SEVERITY, Summary,
                               as_dict, render_json, render_line, render_text)
from certinator.types import (BITSQUAT, COMBOSQUAT, CONTAINS, HOMOGRAPH,
                              SUBDOMAIN, TLDSQUAT, TYPO, Match, Observation)

WHEN = datetime.datetime(2026, 3, 1, 12, 30, tzinfo=datetime.timezone.utc)


def observation(name="paypa1.com", **kw):
    base = dict(name=name, timestamp=WHEN.timestamp(), log="nimbus2026",
                index=42, issuer="Test CA", not_after=WHEN, is_precert=True,
                all_names=(name, f"www.{name}"))
    base.update(kw)
    return Observation(**base)


def match(technique=TYPO, name="paypa1.com", score=0.82, brand="paypal"):
    return Match(observation=observation(name), brand=brand,
                 technique=technique, score=score, detail="one edit away")


def test_every_technique_has_a_severity_and_an_explanation():
    from certinator.report import EXPLANATION
    for technique in (HOMOGRAPH, TLDSQUAT, SUBDOMAIN, BITSQUAT, TYPO,
                      COMBOSQUAT, CONTAINS):
        assert technique in SEVERITY
        assert technique in EXPLANATION


def test_a_homograph_outranks_an_embedded_brand():
    assert SEVERITY[HOMOGRAPH] == CRITICAL
    assert SEVERITY[CONTAINS] == LOW


def test_ranking_puts_the_worst_first():
    summary = Summary(matches=[match(CONTAINS, score=0.6),
                               match(HOMOGRAPH, score=0.97),
                               match(COMBOSQUAT, score=0.78)])
    assert [m.technique for m in summary.ranked()] == [HOMOGRAPH, COMBOSQUAT, CONTAINS]


def test_counts_by_severity():
    summary = Summary(matches=[match(HOMOGRAPH), match(TYPO), match(TYPO)])
    assert summary.counts() == {CRITICAL: 1, HIGH: 2}


def test_text_output_shows_the_evidence():
    summary = Summary(brands=("paypal",), logs=("nimbus2026",),
                      entries=1000, names=2500, matches=[match()])
    text = render_text(summary, colour=False)
    assert "paypa1.com" in text
    assert "one edit away" in text
    assert "impersonates" in text and "paypal" in text
    assert "precertificate" in text
    assert "nimbus2026 #42" in text


def test_text_output_lists_the_other_names_on_the_certificate():
    """A certificate covering several hosts is several problems, and the rest
    of them are where the campaign shows its shape."""
    names = tuple(f"host{i}.evil.example" for i in range(6))
    hit = Match(observation=observation("evil.example", all_names=names),
                brand="paypal", technique=TYPO, score=0.8, detail="x")
    text = render_text(Summary(matches=[hit]), colour=False)
    assert "also covers" in text
    assert "and 3 more" in text


def test_nothing_found_says_what_it_did_not_look_at():
    """Silence has to be qualified, or it reads as an all clear."""
    text = render_text(Summary(brands=("paypal",)), colour=False)
    assert "No impersonations found" in text
    assert "issued earlier are not in the window" in text


def test_parse_failures_are_surfaced_not_swallowed():
    summary = Summary(brands=("paypal",), entries=100, parse_failures=7)
    assert "7 unparseable" in render_text(summary, colour=False)


def test_top_reports_what_it_omitted():
    summary = Summary(matches=[match(TYPO, name=f"a{i}.com") for i in range(10)])
    text = render_text(summary, colour=False, limit=3)
    assert "showing 3 of 10, 7 omitted by --top" in text


def test_json_is_machine_readable_and_complete():
    summary = Summary(brands=("paypal",), logs=("nimbus2026",),
                      entries=10, names=20, matches=[match()])
    data = json.loads(render_json(summary))
    assert data["brands"] == ["paypal"]
    assert data["counts"] == {HIGH: 1}
    entry = data["matches"][0]
    assert entry["name"] == "paypa1.com"
    assert entry["technique"] == TYPO
    assert entry["severity"] == HIGH
    assert entry["precertificate"] is True
    assert entry["log"] == "nimbus2026" and entry["index"] == 42
    assert entry["seen"].startswith("2026-03-01")


def test_json_survives_a_missing_expiry():
    hit = Match(observation=observation(not_after=None), brand="paypal",
                technique=TYPO, score=0.8)
    assert as_dict(hit)["not_after"] is None


def test_live_line_is_one_line():
    line = render_line(match(), colour=False)
    assert "\n" not in line
    assert "paypa1.com" in line and "paypal" in line


def test_colour_can_be_turned_off():
    assert "\033[" not in render_text(Summary(matches=[match()]), colour=False)
    assert "\033[" not in render_line(match(), colour=False)
