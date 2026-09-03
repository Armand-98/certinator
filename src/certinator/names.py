"""Turn a domain name into what a victim sees.

A phishing name only has to survive one glance in an address bar, so the thing
worth comparing is the rendered shape rather than the bytes. Four steps get
there: normalise the syntax, decode the punycode a browser would decode, fold
the characters that render alike onto one Latin skeleton, and cut the name at
its registrable boundary using the Public Suffix List.

Everything here is fed from Certificate Transparency, where any byte sequence
that passed a CA's parser can turn up. Nothing raises on malformed input, every
length is bounded before it is walked, and a name that cannot be decoded is
kept as it stands: an undecodable label is a reason to look harder at an entry,
never a reason to drop it.
"""

from __future__ import annotations

import codecs
import unicodedata

from .suffixes import EXCEPTION, ORDINARY, WILDCARD

# A DNS name is at most 253 octets. Certificates carry longer, and the cap
# bounds every loop below, since each works label by label over this.
MAX_NAME = 1024

# RFC 1035 caps a label at 63 octets, so a longer one was never a real xn--
# label and is not worth handing to a decoder.
MAX_LABEL = 63

# Folding can uncover a label the decoder could not see the first time round,
# so skeleton() repeats until it settles. Real names settle on the first pass.
MAX_FOLD_PASSES = 3

# UTS 46 treats these three as label separators, and the ones after them are
# what NFKD turns into a full stop or an asterisk further down. They are folded
# here so that a name is stripped the same way whether or not it has already
# been through fold_confusables(); that is what keeps skeleton() idempotent.
_SEPARATORS = str.maketrans({
    "。": ".",      # IDEOGRAPHIC FULL STOP
    "．": ".",      # FULLWIDTH FULL STOP
    "｡": ".",      # HALFWIDTH IDEOGRAPHIC FULL STOP
    "﹒": ".",      # SMALL FULL STOP
    "․": ".",      # ONE DOT LEADER
    "‥": "..",     # TWO DOT LEADER
    "…": "...",    # HORIZONTAL ELLIPSIS
    "︰": "..",     # PRESENTATION FORM FOR VERTICAL TWO DOT LEADER
    "︙": "...",    # PRESENTATION FORM FOR VERTICAL HORIZONTAL ELLIPSIS
    "＊": "*",      # FULLWIDTH ASTERISK
    "﹡": "*",      # SMALL ASTERISK
})

# Latin skeleton character, then the code points a browser draws the same way.
#
# Cyrillic and Greek are the confusable pairs from the Unicode security data
# (UTS 39) that survive in an address bar, transcribed by hand: the full
# confusables file is thousands of lines and shipping it would bury this
# decision rather than record it.
#
# The digits are the substitutions phishing kits actually use rather than a
# shape theory, and they are lossy on purpose: 5g.com skeletonises to sg.com,
# which costs a little precision and catches paypa1.com.
#
# The fullwidth block, the circled and superscript forms and every accented
# letter need no entry here; NFKD in fold_confusables() already collapses them.
_GROUPS = {
    "a": "аαɑ",              # Cyrillic a, Greek alpha, Latin alpha
    "b": "вьβ",              # Cyrillic ve, soft sign, Greek beta
    "c": "сϲ",                    # Cyrillic es, Greek lunate sigma
    "d": "ԁđ",                    # Cyrillic komi de, Latin d with stroke
    "e": "еε",                    # Cyrillic ie, Greek epsilon
    "g": "ɡ",                          # Latin script g
    "h": "һн",                    # Cyrillic shha, Cyrillic en (H shaped)
    "i": "іιı",              # Cyrillic i, Greek iota, dotless i
    "j": "јϳ",                    # Cyrillic je, Greek yot
    "k": "кκ",                    # Cyrillic ka, Greek kappa
    "l": "1ӏł|ǀ",            # digit one, Cyrillic palochka,
                                            # l with stroke, pipe, dental click
    "m": "м",                          # Cyrillic em
    "n": "пηո",              # Cyrillic pe, Greek eta, Armenian vo
    "o": "0оοօø",       # digit zero, Cyrillic o, Greek
                                            # omicron, Armenian oh, o with stroke
    "p": "рρ",                    # Cyrillic er, Greek rho
    "q": "ԛ",                          # Cyrillic qa
    "r": "г",                          # Cyrillic ghe, an r in a sans face
    "s": "5ѕ",                         # digit five, Cyrillic dze
    "t": "тτ",                    # Cyrillic te, Greek tau
    "u": "υμս",              # Greek upsilon, Greek mu, Armenian se
    "v": "νѵ",                    # Greek nu, Cyrillic izhitsa
    "w": "ԝω",                    # Cyrillic we, Greek omega
    "x": "хχ",                    # Cyrillic ha, Greek chi
    "y": "уγү",              # Cyrillic u, Greek gamma, straight u
    "-": "‐‑‒–—―⁃−˗֊",
}

_CONFUSABLES = {ord(source): latin
                for latin, group in _GROUPS.items()
                for source in group}

# Pairs of letters read as one. Applied after the single character table so
# that a Cyrillic er folded to r can still form part of an rn.
_DIGRAPHS = (("rn", "m"), ("vv", "w"))


def normalize(name: str) -> str:
    """Lowercase, strip whitespace, the trailing root dot and any wildcard.

    A wildcard certificate for *.evil.com is a statement about evil.com, and
    entries stack the label more than once, hence the loop.
    """
    if len(name) > MAX_NAME:
        name = name[:MAX_NAME]
    name = name.strip().casefold().translate(_SEPARATORS)
    while name.startswith("*."):
        name = name[2:]
    name = name.rstrip(".")
    return "" if name == "*" else name


def to_unicode(name: str) -> str:
    """Decode xn-- labels to the characters a victim sees.

    The stdlib "idna" codec is not usable here: it enforces IDNA 2003 rules and
    raises on names that certificates and browsers accept every day, and this
    module may never raise. So each label is decoded on its own with punycode
    and an undecodable label is left exactly as it was.
    """
    if len(name) > MAX_NAME:
        name = name[:MAX_NAME]
    if "xn--" not in name:
        return name
    return ".".join(_decode_label(label) for label in name.split("."))


def _decode_label(label: str) -> str:
    if not label.startswith("xn--") or len(label) > MAX_LABEL:
        return label
    try:
        decoded = codecs.decode(label[4:].encode("ascii"), "punycode")
    except (UnicodeError, ValueError):
        return label
    return decoded if _displayable(decoded) else label


def _displayable(text: str) -> bool:
    """Whether a decode produced something a browser would render.

    Python's punycode decoder is lenient and returns control characters for
    input that was never punycode: xn--abc decodes to three C1 bytes. A dot
    would change the shape of the name, and an empty label is not a label.
    """
    if not text or "." in text:
        return False
    return all(unicodedata.category(char)[0] not in "CZ" for char in text)


def fold_confusables(text: str) -> str:
    """Map visually confusable characters onto a Latin skeleton."""
    if len(text) > MAX_NAME:
        text = text[:MAX_NAME]
    # Casefolding first, so the table needs only lowercase keys and so nothing
    # after this point can reintroduce a combining mark: casefolding U+0130
    # yields an i and a combining dot, which the next step would otherwise
    # strip only on a second pass.
    text = unicodedata.normalize("NFKD", text.casefold())
    # Marks strip the accents (so paypál and paypal agree) and the C classes
    # strip the invisibles: a zero width joiner or a soft hyphen inside a label
    # is there to break a comparison, not to be seen.
    text = "".join(char for char in text
                   if unicodedata.category(char)[0] not in "MC")
    text = text.translate(_CONFUSABLES)
    for pair, single in _DIGRAPHS:
        text = text.replace(pair, single)
    return text


def skeleton(name: str) -> str:
    """The form the matcher compares: normalised, decoded and folded.

    Folding can expose an xn-- label the decoder could not see, since a
    Cyrillic ha in front of n-- is not an x until it has been folded into one.
    The pass therefore repeats until the name settles, which for anything that
    is not built to defeat this happens immediately.
    """
    text = normalize(name)
    for _ in range(MAX_FOLD_PASSES):
        folded = normalize(fold_confusables(to_unicode(text)))
        if folded == text:
            break
        text = folded
    return text


def labels(name: str) -> list[str]:
    """The labels of a name, left to right. Empty labels are not names."""
    return [label for label in normalize(name).split(".") if label]


def public_suffix(name: str) -> str:
    """The part of a name that anyone may register under, per the PSL."""
    parts = labels(name)
    return ".".join(parts[len(parts) - _suffix_depth(parts):]) if parts else ""


def registrable(name: str) -> str:
    """The public suffix plus the one label to its left: what someone bought.

    Empty when the name is a public suffix in its own right, such as a bare
    TLD or co.uk, because then nobody registered it.
    """
    parts = labels(name)
    depth = _suffix_depth(parts) + 1
    if len(parts) < depth:
        return ""
    return ".".join(parts[len(parts) - depth:])


def subdomain(name: str) -> str:
    """Everything to the left of the registrable domain."""
    parts = labels(name)
    depth = _suffix_depth(parts) + 1
    if len(parts) <= depth:
        return ""
    return ".".join(parts[:len(parts) - depth])


def _suffix_depth(parts: list[str]) -> int:
    """How many trailing labels form the public suffix.

    The PSL algorithm: an exception rule wins outright and drops its leftmost
    label, otherwise the longest matching rule wins, where a wildcard rule
    matches exactly one label in front of its parent. A name matching no rule
    at all falls to the implicit "*", so an unlisted TLD is its own suffix.
    """
    if not parts:
        return 0
    for index in range(len(parts)):
        if ".".join(parts[index:]) in EXCEPTION:
            return len(parts) - index - 1
    for index in range(len(parts)):
        if ".".join(parts[index:]) in ORDINARY:
            return len(parts) - index
        if index + 1 < len(parts) and ".".join(parts[index + 1:]) in WILDCARD:
            return len(parts) - index
    return 1
