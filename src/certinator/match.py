"""Decide whether an observed name is impersonating a protected brand.

Six techniques, checked most specific first, because a name that qualifies for
several should be reported as the strongest thing it is:

  homograph   characters that are not Latin but look like it. paypal spelled
              with a Cyrillic a is the same picture and a different domain, and
              nobody registers one by accident
  tldsquat    the brand exactly, under a domain the brand does not own
  subdomain   the brand as a label beneath somebody else's domain, as in
              paypal.com.secure-login.example. The victim reads left to right
              and stops before the part that matters
  typo        one edit from the brand: a dropped, doubled, swapped or mistyped
              character
  bitsquat    one flipped bit from the brand, which catches the memory errors
              and the deliberate registrations that exploit them
  combosquat  the brand beside a word like login, verify or secure

Speed matters because this runs against every certificate issued on the
internet, several thousand a second. The edit neighbourhood of each brand is
generated once at startup and matched by hash lookup, so the common case is a
set membership test rather than a distance computation.

What this cannot do: a brand that is also an ordinary word will match ordinary
domains, and no amount of scoring fixes that. Brands shorter than
MIN_BRAND_LENGTH are refused outright for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .names import (labels, normalize, registrable, skeleton, subdomain,
                    to_unicode)
from .types import (BITSQUAT, COMBOSQUAT, CONTAINS, HOMOGRAPH, SUBDOMAIN,
                    TLDSQUAT, TYPO, Brand, Match, Observation)

# Below this a brand collides with ordinary words often enough to be useless.
MIN_BRAND_LENGTH = 4

HOSTNAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

# Words that turn a name containing a brand into a name pretending to be one.
DEFAULT_KEYWORDS = frozenset({
    "account", "accounts", "activate", "alert", "app", "auth", "authenticate",
    "billing", "bank", "confirm", "customer", "help", "id", "identity", "info",
    "invoice", "live", "login", "logon", "mail", "manage", "my", "online",
    "pay", "payment", "portal", "recover", "recovery", "refund", "reset",
    "safe", "secure", "security", "service", "services", "signin", "signon",
    "support", "update", "verification", "verify", "wallet", "webmail",
})

SEPARATORS = "-_."

SCORES = {
    HOMOGRAPH: 0.97,
    TLDSQUAT: 0.92,
    SUBDOMAIN: 0.88,
    BITSQUAT: 0.84,
    TYPO: 0.82,
    COMBOSQUAT: 0.78,
    CONTAINS: 0.60,
}


class BrandError(Exception):
    """A brand cannot usefully be watched for."""


@dataclass(frozen=True, slots=True)
class _Prepared:
    brand: Brand
    label: str                   # the brand's skeleton
    edits: frozenset[str]        # everything one edit away
    bitflips: frozenset[str]     # everything one flipped bit away
    keywords: frozenset[str]


class Matcher:
    """Matches observations against a fixed set of brands."""

    def __init__(self, brands: Iterable[Brand], *,
                 keywords: Iterable[str] = DEFAULT_KEYWORDS,
                 min_score: float = 0.0) -> None:
        self.min_score = min_score
        self._prepared: list[_Prepared] = []
        base = frozenset(keywords)

        for brand in brands:
            label = skeleton(brand.name)
            if len(label) < MIN_BRAND_LENGTH:
                raise BrandError(
                    f"{brand.name!r} is too short to watch for; a brand under "
                    f"{MIN_BRAND_LENGTH} characters matches ordinary words")
            edits = edit_neighbourhood(label)
            self._prepared.append(_Prepared(
                brand=brand,
                label=label,
                edits=frozenset(edits - {label}),
                bitflips=frozenset(bitflips(label) - edits - {label}),
                keywords=base | brand.keywords,
            ))

    def __len__(self) -> int:
        return len(self._prepared)

    @property
    def brands(self) -> tuple[str, ...]:
        return tuple(prepared.brand.name for prepared in self._prepared)

    def match(self, observation: Observation) -> Match | None:
        """The strongest impersonation this name amounts to, if any."""
        best: Match | None = None
        for prepared in self._prepared:
            found = self._match_one(observation, prepared)
            if found and (best is None or found.score > best.score):
                best = found
        if best is not None and best.score >= self.min_score:
            return best
        return None

    def matches(self, observations: Iterable[Observation]) -> list[Match]:
        found = (self.match(observation) for observation in observations)
        return [match for match in found if match is not None]

    def _match_one(self, observation: Observation,
                   prepared: _Prepared) -> Match | None:
        name = observation.name
        # Ownership is a fact about names actually controlled, so it is tested
        # against the name as written. Testing it against the folded skeleton
        # is wrong in the worst possible direction: folding is what makes a
        # homograph resemble the real domain, so a Cyrillic spelling of an
        # owned domain folded straight into it and was dismissed as the
        # brand's own certificate.
        raw = normalize(name)
        if owns(prepared.brand, raw):
            return None

        folded = skeleton(name)
        brand = prepared.label
        domain = registrable(folded) or folded
        stem = _stem(folded)

        if stem == brand:
            # Whether folding was needed is the whole difference between a
            # domain registered under another suffix and one dressed up to be
            # misread.
            if _stem(raw) != brand:
                return self._match(observation, prepared, HOMOGRAPH,
                                   f"{to_unicode(raw)} reads as {brand}")
            return self._match(observation, prepared, TLDSQUAT,
                               f"exactly {brand} under {domain}")

        if brand in labels(subdomain(folded)):
            return self._match(observation, prepared, SUBDOMAIN,
                               f"{brand} is a label beneath {domain}")

        if stem in prepared.edits:
            return self._match(observation, prepared, TYPO,
                               f"{stem} is one edit from {brand}", distance=1)

        if stem in prepared.bitflips:
            return self._match(observation, prepared, BITSQUAT,
                               f"{stem} is one flipped bit from {brand}", distance=1)

        if brand in stem:
            words = [part for part in _split(stem) if part and part != brand]
            hit = next((word for word in words if word in prepared.keywords), "")
            if hit:
                return self._match(observation, prepared, COMBOSQUAT,
                                   f"{brand} beside {hit!r} in {stem}")
            return self._match(observation, prepared, CONTAINS,
                               f"{brand} appears in {stem}")
        return None

    def _match(self, observation: Observation, prepared: _Prepared,
               technique: str, detail: str, distance: int = 0) -> Match:
        return Match(observation=observation, brand=prepared.brand.name,
                     technique=technique, score=SCORES[technique],
                     detail=detail, distance=distance)


def owns(brand: Brand, name: str) -> bool:
    """Whether a name belongs to the brand itself.

    Matched on the domain and its subdomains, so a brand that declares
    example.com is not reported for shop.example.com. Without this every
    certificate the brand renews is a finding.
    """
    for own in brand.domains:
        if name == own or name.endswith("." + own):
            return True
    return False


def edit_neighbourhood(word: str) -> set[str]:
    """Every string one edit from word, over the hostname alphabet.

    Generated once per brand so matching is a hash lookup. For a brand of n
    characters this is about 74n strings, which is a few hundred, so the memory
    is irrelevant and the lookup is constant time.
    """
    out: set[str] = set()
    for index in range(len(word)):
        out.add(word[:index] + word[index + 1:])                      # omission
        for char in HOSTNAME_CHARS:
            out.add(word[:index] + char + word[index:])               # insertion
            out.add(word[:index] + char + word[index + 1:])           # replacement
    for char in HOSTNAME_CHARS:
        out.add(word + char)
    for index in range(len(word) - 1):                                # transposition
        out.add(word[:index] + word[index + 1] + word[index] + word[index + 2:])
    return {candidate for candidate in out if candidate}


def bitflips(word: str) -> set[str]:
    """Every string one flipped bit from word that is still a legal hostname.

    Bit flips happen in memory and in transit, and domains one bit from a
    popular one get registered on purpose to catch the traffic.
    """
    out: set[str] = set()
    for index, char in enumerate(word):
        for bit in range(8):
            flipped = chr(ord(char) ^ (1 << bit))
            if flipped in HOSTNAME_CHARS:
                out.add(word[:index] + flipped + word[index + 1:])
    return out - {word}


def _split(stem: str) -> list[str]:
    parts, current = [], ""
    for char in stem:
        if char in SEPARATORS:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return parts


def _stem(name: str) -> str:
    """The label a brand would occupy: everything left of the public suffix."""
    domain = registrable(name)
    return domain.split(".", 1)[0] if domain else name
