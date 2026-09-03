"""Turning log entries into observations, and observations into findings.

Two ways to run. `scan` takes one pass over the most recent entries in each log
and returns what it found, which is what you want when checking whether
something has already happened. `follow` keeps polling for new entries and
reports as they arrive, which is what you want when the answer is "not yet".

A log entry that cannot be parsed is counted and skipped, never fatal. The logs
carry certificates from every authority on earth, some of which encode things
in ways nothing else does, and a monitor that stops at the first surprise
monitors nothing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Sequence

from .ctlog import CtError, Log, entries, tree_size
from .names import registrable
from .leaf import LeafError, parse_leaf
from .match import Matcher
from .report import Summary
from .types import Match, Observation
from .x509 import CertificateError, parse_certificate

DEFAULT_INTERVAL = 30.0
DEFAULT_RECENT = 2000


@dataclass(slots=True)
class Counters:
    entries: int = 0
    names: int = 0
    failures: int = 0
    duplicates: int = 0
    unreadable: int = 0


class _Seen:
    """Collapses repeats onto the thing a person would act on.

    One certificate routinely covers dozens of hosts under one domain, and a
    service renews weekly. Reporting every hostname separately buries the
    finding that matters under fifty restatements of it, so a domain is
    reported the first time it is seen and counted thereafter.
    """

    def __init__(self) -> None:
        self._keys: set[tuple[str, str, str]] = set()

    def is_new(self, match: Match) -> bool:
        key = (match.brand, registrable(match.name) or match.name,
               match.technique)
        if key in self._keys:
            return False
        self._keys.add(key)
        return True


def observations(log_name: str, index: int, leaf_input: bytes,
                 counters: Counters) -> list[Observation]:
    """Every name on one certificate, as observations.

    A certificate covering fifty hosts is fifty chances to be impersonating
    something, so each name is judged on its own.
    """
    try:
        leaf = parse_leaf(leaf_input)
        certificate = parse_certificate(leaf.der)
    except (LeafError, CertificateError):
        counters.failures += 1
        return []

    names = certificate.names
    counters.names += len(names)
    return [
        Observation(
            name=name,
            timestamp=leaf.seconds,
            log=log_name,
            index=index,
            issuer=certificate.issuer,
            not_after=certificate.not_after,
            is_precert=leaf.is_precert,
            all_names=names,
        )
        for name in names
    ]


def scan(logs: Sequence[Log], matcher: Matcher, *, recent: int = DEFAULT_RECENT,
         timeout: float = 30.0,
         on_match: Callable[[Match], None] | None = None) -> Summary:
    """Check the most recent `recent` entries of each log."""
    summary = Summary(brands=tuple(sorted(matcher.brands)),
                      logs=tuple(log.name for log in logs))
    counters = Counters()
    seen = _Seen()

    for log in logs:
        try:
            size = tree_size(log, timeout=timeout)
        except (OSError, CtError):
            counters.unreadable += 1
            continue
        start = max(0, size - recent)
        try:
            for index, leaf_input in entries(log, start, size - 1,
                                             timeout=timeout):
                counters.entries += 1
                for observation in observations(log.name, index, leaf_input,
                                                counters):
                    found = matcher.match(observation)
                    if found is None:
                        continue
                    if not seen.is_new(found):
                        counters.duplicates += 1
                        continue
                    summary.matches.append(found)
                    if on_match:
                        on_match(found)
        except (OSError, CtError):
            # A log that rate limits, disappears or answers with something
            # unreadable costs its own entries, not the whole run.
            counters.unreadable += 1

    summary.entries, summary.names = counters.entries, counters.names
    summary.parse_failures = counters.failures
    summary.duplicates = counters.duplicates
    summary.unreadable_logs = counters.unreadable
    return summary


def follow(logs: Sequence[Log], matcher: Matcher, *,
           interval: float = DEFAULT_INTERVAL, timeout: float = 30.0,
           on_match: Callable[[Match], None] | None = None,
           positions: dict[str, int] | None = None,
           should_stop: Callable[[], bool] | None = None) -> Summary:
    """Poll each log for new entries until told to stop.

    Positions are kept per log and returned in the summary's own dict, so a
    watch that is interrupted can be resumed where it left off rather than
    re-reading or, worse, silently skipping the gap.
    """
    summary = Summary(brands=tuple(sorted(matcher.brands)),
                      logs=tuple(log.name for log in logs))
    counters = Counters()
    seen = _Seen()
    at = dict(positions or {})

    for log in logs:
        if log.name not in at:
            try:
                at[log.name] = tree_size(log, timeout=timeout)
            except (OSError, CtError):
                counters.unreadable += 1
                continue

    while not (should_stop and should_stop()):
        moved = False
        for log in logs:
            start = at.get(log.name)
            if start is None:
                continue
            try:
                size = tree_size(log, timeout=timeout)
            except (OSError, CtError):
                counters.unreadable += 1
                continue
            if size <= start:
                continue
            moved = True
            try:
                for index, leaf_input in entries(log, start, size - 1,
                                                 timeout=timeout):
                    counters.entries += 1
                    at[log.name] = index + 1
                    for observation in observations(log.name, index, leaf_input,
                                                    counters):
                        found = matcher.match(observation)
                        if found is None:
                            continue
                        if not seen.is_new(found):
                            counters.duplicates += 1
                            continue
                        summary.matches.append(found)
                        if on_match:
                            on_match(found)
            except (OSError, CtError):
                # The position is already advanced to the last entry actually
                # read, so the next pass resumes at the gap rather than
                # stepping over it.
                counters.unreadable += 1

        summary.entries, summary.names = counters.entries, counters.names
        summary.parse_failures = counters.failures
        summary.duplicates = counters.duplicates
        summary.unreadable_logs = counters.unreadable
        summary.positions = dict(at)

        if should_stop and should_stop():
            break
        if not moved:
            time.sleep(interval)

    return summary
