"""Types shared across the tool.

The matcher, the log client and the report all speak in these, so a new log
source or a new matching technique does not require touching the others.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

# How a name was judged to impersonate a brand. Ordered by how strongly each
# implies intent: nobody registers a Cyrillic homograph of a bank by accident.
HOMOGRAPH = "homograph"          # different characters, same appearance
TLDSQUAT = "tldsquat"            # the brand exactly, under a domain it does not own
SUBDOMAIN = "subdomain"          # the brand as a label under someone else's domain
TYPO = "typo"                    # one edit away from the brand
BITSQUAT = "bitsquat"            # one flipped bit away from the brand
COMBOSQUAT = "combosquat"        # the brand plus a word like login or secure
CONTAINS = "contains"            # the brand embedded with no other signal


@dataclass(frozen=True, slots=True)
class Observation:
    """One DNS name seen on one certificate in one log."""

    name: str                       # as it appeared, normalised
    timestamp: float                # seconds since the epoch, from the log entry
    log: str = ""                   # short log name, for provenance
    index: int = 0                  # position in that log, so it can be refetched
    issuer: str = ""
    not_after: datetime.datetime | None = None
    is_precert: bool = False
    all_names: tuple[str, ...] = ()  # every name on the same certificate

    @property
    def seen(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(
            self.timestamp, datetime.timezone.utc)


@dataclass(frozen=True, slots=True)
class Match:
    """A name that appears to impersonate a protected brand."""

    observation: Observation
    brand: str
    technique: str
    score: float
    detail: str = ""
    distance: int = 0

    @property
    def name(self) -> str:
        return self.observation.name

    def describe(self) -> str:
        return (f"{self.name}  [{self.technique}] {self.brand} "
                f"score {self.score:.2f}")


@dataclass(frozen=True, slots=True)
class Brand:
    """A brand to protect, and the domains that legitimately belong to it."""

    name: str                                  # the label, for example "paypal"
    domains: frozenset[str] = frozenset()      # never flag these or their subdomains
    keywords: frozenset[str] = frozenset()     # extra combosquat words for this brand

    @staticmethod
    def build(name: str, domains=(), keywords=()) -> "Brand":
        return Brand(name=name.strip().lower(),
                     domains=frozenset(d.strip().lower().rstrip(".") for d in domains),
                     keywords=frozenset(k.strip().lower() for k in keywords))
