"""Name normalisation tests.

Confusable characters are written as escapes throughout. A test that pins a
Cyrillic homograph is worthless if the reader cannot tell it apart from the
Latin one, which is the whole point of the attack it describes.

The public suffix cases are the ones that break a last-two-labels shortcut:
a two label suffix (co.uk), a wildcard rule (*.ck), the exception that
overrides it (!www.ck), and a suffix that is in no list at all.
"""

import codecs
import importlib.util
import unicodedata
from pathlib import Path

import pytest

from certinator.names import (MAX_LABEL, MAX_NAME, _GROUPS, fold_confusables,
                              labels, normalize, public_suffix, registrable,
                              skeleton, subdomain, to_unicode)

CYRILLIC_PAYPAL = "раураl.com"   # ра у ра + Latin l
GREEK_PAYPAL = "ραyραl.com"           # rho alpha rho alpha
FULLWIDTH = "ｐａｙｐａｌ.com"    # ｐａｙｐａｌ
APPLE_PUNYCODE = "xn--80ak6aa92e"                         # аррӏе, all Cyrillic


@pytest.mark.parametrize("raw, expected", [
    ("PayPal.COM", "paypal.com"),
    ("  paypal.com  ", "paypal.com"),
    ("paypal.com.", "paypal.com"),
    ("*.paypal.com", "paypal.com"),
    ("*.*.paypal.com", "paypal.com"),
    ("*.PAYPAL.com.", "paypal.com"),
    ("*", ""),
    ("*.", ""),
    ("", ""),
    ("\n\tpaypal.com\r\n", "paypal.com"),
])
def test_normalize(raw, expected):
    assert normalize(raw) == expected


def test_normalize_folds_separators_that_are_not_full_stops():
    # A browser treats the ideographic full stop as a label separator, so a
    # name ending in one is still a name with a trailing root dot.
    assert normalize("evil。com。") == "evil.com"
    assert normalize("＊。evil.com") == "evil.com"


def test_normalize_bounds_an_absurd_name():
    assert len(normalize("a" * (MAX_NAME * 10))) == MAX_NAME


def test_to_unicode_decodes():
    assert to_unicode(APPLE_PUNYCODE + ".com") == "аррӏе.com"


@pytest.mark.parametrize("name", [
    "xn--abc.com",       # decodes, but only to C1 control characters
    "xn--.com",          # decodes to nothing
    "xn--..-.com",       # decodes to dots, which would reshape the name
    "xn--a-ecṕ.com",  # not ASCII, so not punycode at all
    "xn--" + "a" * 70 + ".com",   # longer than a DNS label can be
])
def test_to_unicode_keeps_a_label_it_cannot_decode(name):
    """An undecodable label is a reason to look harder, never a reason to drop."""
    assert to_unicode(name) == name


def test_to_unicode_decodes_a_prefix_written_in_any_case():
    """DNS is case insensitive, so a certificate can spell the prefix XN--."""
    assert to_unicode(APPLE_PUNYCODE.upper() + ".COM") == "аррӏе.COM"


def test_to_unicode_leaves_ordinary_names_alone():
    assert to_unicode("www.paypal.com") == "www.paypal.com"
    assert to_unicode("") == ""


@pytest.mark.parametrize("hostile", [
    "xn--\ud800.com", "xn--" * 200, "�.xn--", "xn---", "xn--0-",
    "..xn--..", "\x00xn--abc", "xn--" + "а" * 60,
])
def test_to_unicode_never_raises(hostile):
    assert isinstance(to_unicode(hostile), str)


@pytest.mark.parametrize("raw, expected", [
    (CYRILLIC_PAYPAL, "paypal.com"),
    (GREEK_PAYPAL, "paypal.com"),
    (FULLWIDTH, "paypal.com"),
    ("paypál.com", "paypal.com"),          # combining acute, via NFKD
    ("pay​pal.com", "paypal.com"),         # zero width space
    ("pay­pal.com", "paypal.com"),         # soft hyphen
    ("paypa1.c0m", "paypal.com"),               # one for l, zero for o
    ("micro5oft", "microsoft"),                 # five for s
    ("rnicrosoft", "microsoft"),                # rn read as m
    ("vvellsfargo", "wellsfargo"),
    ("PayPal.com", "paypal.com"),
])
def test_fold_confusables(raw, expected):
    assert fold_confusables(raw) == expected


def test_every_confusable_in_the_table_folds_to_its_target():
    """An entry casefold rewrites first is an entry that can never fire.

    U+03F2 GREEK LUNATE SIGMA SYMBOL is drawn exactly like a Latin c, but it
    casefolds to U+03C2 FINAL SIGMA before the table is consulted, so listing
    the lunate form alone leaves the character unfolded.
    """
    for latin, group in _GROUPS.items():
        for source in group:
            assert fold_confusables(source) == latin, f"U+{ord(source):04X}"


def test_greek_lunate_sigma_reads_as_c():
    assert skeleton("\u03f2hase.com") == "chase.com"


@pytest.mark.parametrize("raw, expected", [
    ("\u1d3eaypal.com", "paypal.com"),      # MODIFIER LETTER CAPITAL P
    ("\u1d39icrosoft.com", "microsoft.com"),  # MODIFIER LETTER CAPITAL M
])
def test_fold_handles_a_decomposition_that_yields_a_capital(raw, expected):
    """NFKD runs after casefold and can hand back an uppercase letter.

    U+1D3E decomposes to a bare P, which no lowercase table key matches.
    """
    assert fold_confusables(raw) == expected


@pytest.mark.parametrize("block", [
    range(0x0370, 0x0400),    # Greek, where the symbol forms decompose
    range(0x1d00, 0x1d80),    # phonetic extensions, the modifier capitals
    range(0x2100, 0x2150),    # letterlike symbols
    range(0xff00, 0xff60),    # fullwidth
])
def test_fold_is_idempotent_over_the_blocks_that_decompose(block):
    for code_point in block:
        once = fold_confusables(chr(code_point))
        assert fold_confusables(once) == once, f"U+{code_point:04X}"


def test_fold_leaves_a_plain_name_untouched():
    assert fold_confusables("paypal.com") == "paypal.com"


def test_fold_bounds_an_absurd_name():
    assert len(fold_confusables("а" * (MAX_NAME * 10))) == MAX_NAME


def test_skeleton_is_the_whole_chain():
    assert skeleton("*." + APPLE_PUNYCODE + ".COM.") == "apple.com"
    assert skeleton(CYRILLIC_PAYPAL) == skeleton("paypal.com") == "paypal.com"


def test_skeleton_folds_a_hidden_punycode_label():
    """A Cyrillic ha in front of n-- is only an xn-- label once it is folded.

    xn--pple-43d is Cyrillic a then pple, so the first pass folds the leading
    character into an x and the second pass is the one that decodes the label.
    """
    assert skeleton("хn--pple-43d.com") == "apple.com"


def _nest(label: str, depth: int) -> str:
    for _ in range(depth):
        label = "xn--" + codecs.encode(label, "punycode").decode("ascii")
    return label


@pytest.mark.parametrize("depth", range(1, 12))
def test_skeleton_settles_on_stacked_punycode(depth):
    """Each xn-- wrap costs five characters, so a 63 octet label holds twelve.

    Stopping the fold before a name settles leaves an xn-- label in the
    skeleton, which is both a name the matcher never resolves and a skeleton
    that is not its own skeleton.
    """
    name = _nest("apple", depth) + ".com"
    assert len(name.partition(".")[0]) <= MAX_LABEL
    once = skeleton(name)
    assert once == "apple.com"
    assert skeleton(once) == once


IDEMPOTENCE_CORPUS = [
    "", "*", "*.*.evil.com", "paypal.com.", "www.foo.co.uk", CYRILLIC_PAYPAL,
    GREEK_PAYPAL, FULLWIDTH, APPLE_PUNYCODE + ".com", "xn--abc.com", "xn--",
    "хn--80ak6aa92e.com", "evil。com", "paypál​.com",
    "＊．evil.com", "paýpal.com", "İstanbul.com",
    "a" * 300 + ".com", "..a..b..", "��.com", "0-1-5.rn.com",
    "…evil.com", "ẞ.com", "xn--\ud800.com",
    # U+2488 decomposes onto "1." and U+33C7 onto "Co.", so NFKD uncovers a
    # full stop that normalize() never saw and no browser splits a label on.
    "evil\u2488com", "\u2488\u2488evil.com", "evil.com\u33c7",
]


@pytest.mark.parametrize("raw", IDEMPOTENCE_CORPUS)
def test_skeleton_is_idempotent(raw):
    once = skeleton(raw)
    assert skeleton(once) == once


@pytest.mark.parametrize("raw", IDEMPOTENCE_CORPUS)
def test_skeleton_output_holds_no_marks_or_invisibles(raw):
    assert all(unicodedata.category(char)[0] not in "MC" for char in skeleton(raw))


def test_labels():
    assert labels("WWW.Foo.CO.UK.") == ["www", "foo", "co", "uk"]
    assert labels("*.evil.com") == ["evil", "com"]
    assert labels("") == []
    assert labels("..a..b..") == ["a", "b"]


@pytest.mark.parametrize("name, suffix, domain, sub", [
    ("paypal.com", "com", "paypal.com", ""),
    ("www.paypal.com", "com", "paypal.com", "www"),
    ("login.secure.paypal.com", "com", "paypal.com", "login.secure"),
    ("foo.co.uk", "co.uk", "foo.co.uk", ""),
    ("www.foo.co.uk", "co.uk", "foo.co.uk", "www"),
    ("shop.example.com.au", "com.au", "example.com.au", "shop"),
    # github.io lives in the private section of the list, which is not shipped:
    # a page under it is someone else's registrable domain, and saying so is
    # what lets the matcher call brand.github.io a subdomain attack.
    ("a.b.github.io", "io", "github.io", "a.b"),
    ("com", "com", "", ""),                     # a bare TLD is nobody's domain
    ("co.uk", "co.uk", "", ""),
    ("localhost", "localhost", "", ""),         # single label, in no list
    ("", "", "", ""),
    ("evil.wtfisthis", "wtfisthis", "evil.wtfisthis", ""),   # unlisted suffix
    ("a.evil.wtfisthis", "wtfisthis", "evil.wtfisthis", "a"),
    ("*.evil.com", "com", "evil.com", ""),
    ("paypal.com.", "com", "paypal.com", ""),
])
def test_public_suffix_boundary(name, suffix, domain, sub):
    assert public_suffix(name) == suffix
    assert registrable(name) == domain
    assert subdomain(name) == sub


@pytest.mark.parametrize("name, suffix, domain", [
    ("ck", "ck", ""),                # the wildcard needs a label to eat
    ("a.ck", "a.ck", ""),            # *.ck, so a.ck is a public suffix
    ("b.a.ck", "a.ck", "b.a.ck"),
    ("www.ck", "ck", "www.ck"),      # !www.ck overrides the wildcard
    ("a.www.ck", "ck", "www.ck"),
])
def test_wildcard_and_exception_rules(name, suffix, domain):
    assert public_suffix(name) == suffix
    assert registrable(name) == domain


def test_registrable_of_a_homograph_is_the_registered_name():
    """The skeleton is for comparing; the boundary is for the real name."""
    assert registrable(APPLE_PUNYCODE + ".com") == APPLE_PUNYCODE + ".com"
    assert registrable(skeleton(APPLE_PUNYCODE + ".com")) == "apple.com"


def test_a_name_of_many_labels_terminates():
    name = "a." * 400 + "com"
    assert registrable(name) == "a.com"
    assert subdomain(name) == ".".join(["a"] * 399)


def test_a_name_past_the_bound_is_cut_rather_than_walked():
    name = "a." * 5000 + "com"
    assert len(normalize(name)) <= MAX_NAME    # the cut may land on a dot
    assert registrable(name) == "a.a"         # whatever the cut left behind
    assert skeleton(name) == normalize(name)


PSL_EXCERPT = """\
// ===BEGIN ICANN DOMAINS===
// com : example
com
co.uk
uk
*.ck
!www.ck
рф
// a comment
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""


def load_builder():
    path = Path(__file__).resolve().parent.parent / "tools" / "build_suffixes.py"
    spec = importlib.util.spec_from_file_location("build_suffixes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_builder_keeps_the_icann_section_only():
    """Built from a hand written excerpt, so the parse is checked, not the net."""
    builder = load_builder()
    ordinary, wildcard, exception = builder.classify(
        builder.icann_rules(PSL_EXCERPT))
    assert ordinary == {"com", "co.uk", "uk", "рф", "xn--p1ai"}
    assert wildcard == {"ck"}
    assert exception == {"www.ck"}
    assert "github.io" not in ordinary


def test_builder_rejects_a_list_with_no_icann_section():
    builder = load_builder()
    with pytest.raises(SystemExit):
        builder.icann_rules("com\nco.uk\n")


def test_generated_module_matches_the_builder():
    """The committed rules are what the shipped lookup uses."""
    from certinator import suffixes
    assert "com" in suffixes.ORDINARY
    assert "xn--p1ai" in suffixes.ORDINARY and "рф" in suffixes.ORDINARY
    assert "ck" in suffixes.WILDCARD
    assert "www.ck" in suffixes.EXCEPTION
    assert "github.io" not in suffixes.ORDINARY
