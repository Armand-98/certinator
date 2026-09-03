"""Matcher tests.

Positive cases are the shapes real phishing registrations take. The negative
cases matter more: a brand monitor that cries wolf on the brand's own
certificates gets switched off in a week.
"""

import pytest

from certinator.match import (BrandError, DEFAULT_KEYWORDS, MIN_BRAND_LENGTH,
                              Matcher, bitflips, edit_neighbourhood, owns)
from certinator.types import (BITSQUAT, COMBOSQUAT, CONTAINS, HOMOGRAPH,
                              SUBDOMAIN, TLDSQUAT, TYPO, Brand, Observation)

PAYPAL = Brand.build("paypal", ["paypal.com", "paypal.co.uk", "paypalobjects.com"])


def seen(name):
    return Observation(name=name, timestamp=1_700_000_000.0)


def hit(matcher, name):
    return matcher.match(seen(name))


@pytest.fixture
def matcher():
    return Matcher([PAYPAL])


# --- the brand's own certificates ------------------------------------------

@pytest.mark.parametrize("name", [
    "paypal.com", "www.paypal.com", "shop.paypal.com",
    "a.b.c.paypal.com", "paypal.co.uk", "www.paypal.co.uk",
    "paypalobjects.com", "cdn.paypalobjects.com",
])
def test_the_brands_own_names_are_never_flagged(matcher, name):
    assert hit(matcher, name) is None


def test_owns_matches_subdomains_not_prefixes():
    assert owns(PAYPAL, "paypal.com")
    assert owns(PAYPAL, "login.paypal.com")
    assert not owns(PAYPAL, "notpaypal.com")
    assert not owns(PAYPAL, "paypal.com.evil.example")


# --- unrelated traffic -----------------------------------------------------

@pytest.mark.parametrize("name", [
    "example.com", "github.com", "some-random-startup.io",
    "mail.google.com", "cdn.jsdelivr.net", "a.very.deep.subdomain.example.org",
])
def test_ordinary_names_are_not_flagged(matcher, name):
    assert hit(matcher, name) is None


# --- techniques ------------------------------------------------------------

def test_exact_brand_under_a_foreign_domain(matcher):
    found = hit(matcher, "paypal.xyz")
    assert found.technique == TLDSQUAT
    assert found.score == pytest.approx(0.92)


@pytest.mark.parametrize("name,stem", [
    ("paypbl.com", "paypbl"),      # replacement
    ("paypall.net", "paypall"),    # insertion
    ("paypl.com", "paypl"),        # omission
    ("apypal.org", "apypal"),      # transposition
])
def test_one_edit_away_is_a_typo(matcher, name, stem):
    found = hit(matcher, name)
    assert found.technique == TYPO
    assert found.distance == 1
    assert stem in found.detail


def test_brand_as_a_label_under_someone_elses_domain(matcher):
    """The victim reads left to right and stops before the part that decides
    where the request goes."""
    found = hit(matcher, "paypal.com.secure-login.example")
    assert found.technique == SUBDOMAIN
    assert "secure-login.example" in found.detail


def test_brand_beside_a_phishing_keyword(matcher):
    found = hit(matcher, "secure-paypal-login.com")
    assert found.technique == COMBOSQUAT
    assert "secure" in found.detail


def test_brand_embedded_with_no_other_signal_is_weak(matcher):
    found = hit(matcher, "paypaltoys.com")
    assert found.technique == CONTAINS
    assert found.score < 0.7, "an embedded brand alone is not evidence of intent"


def test_the_strongest_technique_wins(matcher):
    """A name that qualifies several ways is reported as the worst of them."""
    found = hit(matcher, "paypal.com.login-verify.example")
    assert found.technique == SUBDOMAIN


# --- the neighbourhoods ----------------------------------------------------

def test_edit_neighbourhood_covers_all_four_edits():
    edits = edit_neighbourhood("paypal")
    assert "paypl" in edits          # omission
    assert "paypall" in edits        # insertion
    assert "paypa1" in edits         # replacement
    assert "apypal" in edits         # transposition
    assert "paypal" not in edit_neighbourhood("paypal") - {"paypal"}


def test_edit_neighbourhood_stays_in_the_hostname_alphabet():
    for candidate in edit_neighbourhood("paypal"):
        assert all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in candidate)


def test_edit_neighbourhood_has_no_empty_string():
    assert "" not in edit_neighbourhood("ab")


def test_bitflips_are_legal_hostnames_and_exclude_the_original():
    flips = bitflips("paypal")
    assert "paypal" not in flips
    for candidate in flips:
        assert len(candidate) == len("paypal")
        assert all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in candidate)


def test_bitflips_and_edits_do_not_overlap_in_reporting(matcher):
    """A single character change is both a bit flip and an edit. Reporting it
    as a typo keeps one registration from being counted twice."""
    for candidate in bitflips("paypal"):
        found = hit(matcher, f"{candidate}.com")
        assert found is not None
        assert found.technique in (TYPO, BITSQUAT)


# --- brands ----------------------------------------------------------------

def test_short_brands_are_refused():
    """A three letter brand matches ordinary words constantly, and no scoring
    rescues it."""
    with pytest.raises(BrandError, match="too short"):
        Matcher([Brand.build("abc")])


def test_minimum_brand_length_is_enforced_at_the_boundary():
    Matcher([Brand.build("a" * MIN_BRAND_LENGTH)])
    with pytest.raises(BrandError):
        Matcher([Brand.build("a" * (MIN_BRAND_LENGTH - 1))])


def test_several_brands_are_watched_at_once():
    matcher = Matcher([PAYPAL, Brand.build("netflix", ["netflix.com"])])
    assert len(matcher) == 2
    assert hit(matcher, "netfIix.com") is not None
    assert hit(matcher, "paypa1.com").brand == "paypal"
    assert hit(matcher, "netflix.com") is None


@pytest.mark.parametrize("name", [
    "\u0440aypal.com",      # Cyrillic er
    "pa\u0443pal.com",      # Cyrillic u
    "paypa1.com",           # digit one for the letter l
])
def test_a_homograph_of_an_owned_domain_is_still_reported(matcher, name):
    """The bug this pins was the worst one possible here.

    Ownership used to be tested against the folded skeleton, and folding is
    exactly what makes a homograph resemble the real domain. Every Cyrillic or
    digit-substituted spelling of an owned domain folded into it and was
    dismissed as the brand's own certificate, so the one thing this tool exists
    to catch was the one thing it silently threw away.
    """
    found = hit(matcher, name)
    assert found is not None, f"{name!r} was suppressed"
    assert found.technique == HOMOGRAPH
    assert found.score > 0.9


def test_exactly_the_brand_is_a_tldsquat_not_a_homograph(matcher):
    """Folding changed nothing, so nothing was disguised."""
    assert hit(matcher, "paypal.xyz").technique == TLDSQUAT


def test_a_capital_i_is_a_typo_and_not_a_homograph(matcher):
    """paypaI.com looks identical to paypal.com in many fonts, but DNS is
    case-insensitive, so the domain that got registered really is paypai.com.
    There is no disguise to see through, only a substituted letter."""
    found = hit(matcher, "paypaI.com")
    assert found.technique == TYPO


def test_brand_specific_keywords():
    matcher = Matcher([Brand.build("paypal", ["paypal.com"], keywords=["giftcard"])])
    found = hit(matcher, "paypal-giftcard.com")
    assert found.technique == COMBOSQUAT
    assert "giftcard" in found.detail


def test_min_score_filters(matcher):
    assert hit(matcher, "paypaltoys.com") is not None
    strict = Matcher([PAYPAL], min_score=0.8)
    assert strict.match(seen("paypaltoys.com")) is None
    assert strict.match(seen("paypal.xyz")) is not None


def test_matches_filters_out_the_misses(matcher):
    names = ["paypal.com", "paypa1.com", "example.com", "paypal.xyz"]
    found = matcher.matches(seen(n) for n in names)
    assert sorted(m.name for m in found) == ["paypa1.com", "paypal.xyz"]


# --- shapes that must not raise --------------------------------------------

@pytest.mark.parametrize("name", [
    "", ".", "..", "a", "-", "*.paypal.com", "xn--80ak6aa92e.com",
    "a" * 300 + ".com", ".".join("x" * 60 for _ in range(50)),
])
def test_odd_names_are_survived(matcher, name):
    matcher.match(seen(name))


def test_default_keywords_are_lowercase_words():
    for word in DEFAULT_KEYWORDS:
        assert word == word.lower() and word.isalpha()
