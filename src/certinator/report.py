"""Rendering matches.

Every finding shows the technique that fired and the name it fired against, so
a result can be argued with. A brand monitor that says "suspicious" and stops
gets ignored, because the person reading it cannot tell a homograph of their
bank from a partner's marketing subdomain.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Sequence

from .types import (BITSQUAT, COMBOSQUAT, CONTAINS, HOMOGRAPH, SUBDOMAIN,
                    TLDSQUAT, TYPO, Match)

CRITICAL, HIGH, MEDIUM, LOW = "critical", "high", "medium", "low"
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

_COLOURS = {CRITICAL: "\033[1;31m", HIGH: "\033[31m",
            MEDIUM: "\033[33m", LOW: "\033[36m"}
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"

# What each technique implies about intent. A homograph is a deliberate act; a
# brand appearing inside a longer word frequently is not.
SEVERITY = {
    HOMOGRAPH: CRITICAL,
    TLDSQUAT: HIGH,
    SUBDOMAIN: HIGH,
    BITSQUAT: HIGH,
    TYPO: HIGH,
    COMBOSQUAT: MEDIUM,
    CONTAINS: LOW,
}

EXPLANATION = {
    HOMOGRAPH: "characters that are not Latin but read as it",
    TLDSQUAT: "the brand exactly, under a domain it does not own",
    SUBDOMAIN: "the brand as a label beneath someone else's domain",
    BITSQUAT: "one flipped bit from the brand",
    TYPO: "one edit from the brand",
    COMBOSQUAT: "the brand beside a phishing keyword",
    CONTAINS: "the brand embedded, with no other signal",
}


@dataclass(slots=True)
class Summary:
    brands: tuple[str, ...] = ()
    logs: tuple[str, ...] = ()
    entries: int = 0
    names: int = 0
    parse_failures: int = 0
    duplicates: int = 0
    matches: list[Match] = field(default_factory=list)
    # Where each log was read up to, so an interrupted watch resumes at the
    # gap rather than re-reading it or silently stepping over it.
    positions: dict[str, int] = field(default_factory=dict)

    def ranked(self) -> list[Match]:
        return sorted(self.matches,
                      key=lambda m: (_ORDER[SEVERITY[m.technique]], -m.score))

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for match in self.matches:
            level = SEVERITY[match.technique]
            counts[level] = counts.get(level, 0) + 1
        return counts


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def as_dict(match: Match) -> dict:
    observation = match.observation
    return {
        "name": match.name,
        "brand": match.brand,
        "technique": match.technique,
        "severity": SEVERITY[match.technique],
        "score": round(match.score, 4),
        "detail": match.detail,
        "seen": observation.seen.isoformat(),
        "issuer": observation.issuer,
        "log": observation.log,
        "index": observation.index,
        "precertificate": observation.is_precert,
        "not_after": observation.not_after.isoformat() if observation.not_after else None,
        "certificate_names": list(observation.all_names),
    }


def render_json(summary: Summary) -> str:
    return json.dumps({
        "brands": list(summary.brands),
        "logs": list(summary.logs),
        "entries": summary.entries,
        "names": summary.names,
        "parse_failures": summary.parse_failures,
        "suppressed_duplicates": summary.duplicates,
        "counts": summary.counts(),
        "matches": [as_dict(m) for m in summary.ranked()],
    }, indent=2)


def render_line(match: Match, colour: bool = False) -> str:
    """One finding on one line, for a live watch."""
    paint = _painter(colour)
    level = SEVERITY[match.technique]
    stamp = match.observation.seen.strftime("%H:%M:%S")
    tag = paint(f"{level.upper():8}", _COLOURS[level])
    return (f"  {paint(stamp, _DIM)} {tag} {paint(match.name, _BOLD)}  "
            f"{match.technique} of {match.brand}")


def render_text(summary: Summary, *, colour: bool | None = None,
                limit: int | None = None) -> str:
    colour = use_colour() if colour is None else colour
    paint = _painter(colour)
    lines: list[str] = []

    lines.append(paint(f"certinator  watching {', '.join(summary.brands)}", _BOLD))
    detail = (f"  {summary.entries:,} log entries, {summary.names:,} names, "
              f"{len(summary.logs)} logs")
    if summary.parse_failures:
        detail += f", {summary.parse_failures:,} unparseable"
    if summary.duplicates:
        detail += f", {summary.duplicates:,} repeats of a domain already shown"
    lines.append(paint(detail, _DIM))
    lines.append("")

    matches = summary.ranked()
    shown = matches if limit is None else matches[:limit]
    if not matches:
        lines.append("  No impersonations found.")
        lines.append(paint("  A brand is only watched from the moment you start "
                           "watching it; certificates issued earlier are not in "
                           "the window.", _DIM))
        return "\n".join(lines) + "\n"

    counts = summary.counts()
    tally = "  ".join(f"{paint(level, _COLOURS[level])} {counts[level]}"
                      for level in (CRITICAL, HIGH, MEDIUM, LOW) if level in counts)
    lines.append(f"  {tally}")
    if len(shown) < len(matches):
        lines.append(paint(f"  showing {len(shown)} of {len(matches)}, "
                           f"{len(matches) - len(shown)} omitted by --top", _DIM))
    lines.append("")

    for match in shown:
        level = SEVERITY[match.technique]
        observation = match.observation
        lines.append(f"  {paint(f'[{level.upper()}]', _COLOURS[level])} "
                     f"{paint(match.name, _BOLD)}")
        lines.append(paint(f"        {match.technique}, "
                           f"{EXPLANATION[match.technique]}", _DIM))
        lines.append(f"        {'impersonates':<16} {match.brand}")
        lines.append(f"        {'why':<16} {match.detail}")
        if observation.timestamp:
            lines.append(f"        {'issued':<16} "
                         f"{observation.seen:%Y-%m-%d %H:%M:%S} UTC"
                         f"{' (precertificate)' if observation.is_precert else ''}")
        if observation.issuer:
            lines.append(f"        {'issuer':<16} {observation.issuer}")
        if observation.not_after:
            lines.append(f"        {'expires':<16} {observation.not_after:%Y-%m-%d}")
        others = [n for n in observation.all_names if n != match.name]
        if others:
            shown_names = ", ".join(others[:3])
            if len(others) > 3:
                shown_names += f", and {len(others) - 3} more"
            lines.append(f"        {'also covers':<16} {shown_names}")
        if observation.log:
            lines.append(f"        {'log':<16} {observation.log} #{observation.index}")
        lines.append("")

    return "\n".join(lines)


def _painter(colour: bool):
    if not colour:
        return lambda text, _code="": text
    return lambda text, code="": f"{code}{text}{_RESET}" if code else text
