"""Watch engine tests. No network: log entries are built from real wire bytes."""

import struct
from unittest.mock import patch

import pytest

from certinator.ctlog import Log
from certinator.match import Matcher
from certinator.report import Summary
from certinator.types import Brand
from certinator.watch import Counters, observations, scan

from test_x509 import certificate, san_extension


def leaf_bytes(der, *, precert=False, timestamp=1_700_000_000_000):
    out = bytes([0, 0]) + struct.pack(">QH", timestamp, 1 if precert else 0)
    if precert:
        out += b"\xaa" * 32
    return out + len(der).to_bytes(3, "big") + der + struct.pack(">H", 0)


def cert_leaf(*names, precert=False, cn=""):
    der = certificate(subject_cn=cn or names[0], issuer_cn="Test CA",
                      extensions=(san_extension(*names),))
    return leaf_bytes(der, precert=precert)


def test_every_name_on_a_certificate_becomes_an_observation():
    """A certificate covering fifty hosts is fifty chances to be impersonating
    something, so each name is judged on its own."""
    counters = Counters()
    found = observations("nimbus", 7, cert_leaf("a.example", "b.example",
                                                "c.example"), counters)
    assert [o.name for o in found] == ["a.example", "b.example", "c.example"]
    assert counters.names == 3
    assert all(o.log == "nimbus" and o.index == 7 for o in found)
    assert all(o.all_names == ("a.example", "b.example", "c.example")
               for o in found)


def test_precertificates_are_read_not_skipped():
    counters = Counters()
    found = observations("nimbus", 1, cert_leaf("p.example", precert=True),
                         counters)
    assert found and found[0].is_precert


def test_issuer_and_expiry_travel_with_the_observation():
    counters = Counters()
    (found,) = observations("nimbus", 1, cert_leaf("x.example"), counters)
    assert found.issuer == "Test CA"
    assert found.not_after is not None


@pytest.mark.parametrize("payload", [
    b"", b"\x00", b"\xff" * 40,
    b"\x00\x00" + struct.pack(">QH", 1, 0) + b"\xff\xff\xff",
])
def test_an_unparseable_entry_is_counted_and_skipped(payload):
    """These logs carry certificates from every authority on earth. A monitor
    that stops at the first surprise monitors nothing."""
    counters = Counters()
    assert observations("nimbus", 1, payload, counters) == []
    assert counters.failures == 1


def test_a_bad_entry_does_not_stop_the_ones_after_it():
    counters = Counters()
    assert observations("l", 1, b"\xff" * 10, counters) == []
    assert len(observations("l", 2, cert_leaf("good.example"), counters)) == 1
    assert counters.failures == 1 and counters.names == 1


# --- scanning --------------------------------------------------------------

def fake_log():
    return Log(name="testlog", url="https://ct.example/", operator="Test")


def test_scan_reports_matches_and_counts_what_it_read():
    entries = [(i, cert_leaf(name)) for i, name in enumerate(
        ["paypa1.com", "example.org", "paypal.com.login.example"])]
    matcher = Matcher([Brand.build("paypal", ["paypal.com"])], min_score=0.7)

    with patch("certinator.watch.tree_size", return_value=3), \
         patch("certinator.watch.entries", return_value=entries):
        summary = scan([fake_log()], matcher, recent=10)

    assert summary.entries == 3
    assert sorted(m.name for m in summary.matches) == [
        "paypa1.com", "paypal.com.login.example"]
    assert summary.brands == ("paypal",)


def test_repeats_of_a_domain_are_collapsed_and_counted():
    """One certificate covers dozens of hosts and services renew weekly.
    Reporting each hostname buries the finding under restatements of it."""
    names = ["a.paypa1.com", "b.paypa1.com", "c.paypa1.com"]
    entries = [(i, cert_leaf(n)) for i, n in enumerate(names)]
    matcher = Matcher([Brand.build("paypal", ["paypal.com"])], min_score=0.7)

    with patch("certinator.watch.tree_size", return_value=3), \
         patch("certinator.watch.entries", return_value=entries):
        summary = scan([fake_log()], matcher, recent=10)

    assert len(summary.matches) == 1
    assert summary.duplicates == 2


def test_a_log_that_cannot_be_reached_is_skipped_not_fatal():
    matcher = Matcher([Brand.build("paypal", ["paypal.com"])])
    with patch("certinator.watch.tree_size", side_effect=OSError("down")):
        summary = scan([fake_log()], matcher, recent=10)
    assert summary.matches == []
    assert summary.entries == 0


def test_on_match_is_called_as_findings_arrive():
    entries = [(0, cert_leaf("paypa1.com"))]
    matcher = Matcher([Brand.build("paypal", ["paypal.com"])], min_score=0.7)
    live = []
    with patch("certinator.watch.tree_size", return_value=1), \
         patch("certinator.watch.entries", return_value=entries):
        scan([fake_log()], matcher, recent=10, on_match=live.append)
    assert [m.name for m in live] == ["paypa1.com"]


def test_parse_failures_reach_the_summary():
    entries = [(0, b"\xff" * 12), (1, cert_leaf("paypa1.com"))]
    matcher = Matcher([Brand.build("paypal", ["paypal.com"])], min_score=0.7)
    with patch("certinator.watch.tree_size", return_value=2), \
         patch("certinator.watch.entries", return_value=entries):
        summary = scan([fake_log()], matcher, recent=10)
    assert summary.parse_failures == 1
    assert len(summary.matches) == 1


def test_a_log_that_raises_a_ct_error_is_skipped_not_fatal():
    """CtError derives from Exception, not OSError, so an OSError guard alone
    caught nothing and one rate-limited log took the whole run with it."""
    from certinator.ctlog import CtError
    matcher = Matcher([Brand.build("paypal", ["paypal.com"])])
    with patch("certinator.watch.tree_size", side_effect=CtError("429")):
        summary = scan([fake_log()], matcher, recent=10)
    assert summary.matches == []
    assert summary.unreadable_logs == 1


def test_a_log_failing_partway_costs_only_its_own_entries():
    def blows_up(*_args, **_kwargs):
        yield (0, cert_leaf("paypa1.com"))
        raise CtError("log went away")

    from certinator.ctlog import CtError
    matcher = Matcher([Brand.build("paypal", ["paypal.com"])], min_score=0.7)
    with patch("certinator.watch.tree_size", return_value=5), \
         patch("certinator.watch.entries", blows_up):
        summary = scan([fake_log()], matcher, recent=10)

    assert [m.name for m in summary.matches] == ["paypa1.com"]
    assert summary.unreadable_logs == 1
