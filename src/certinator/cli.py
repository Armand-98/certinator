"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from .ctlog import CtError, discover
from .match import BrandError, Matcher
from .menu import TUTORIAL, ask, interactive
from .menu import run as run_menu
from .report import (SEVERITY, Summary, render_json, render_line, render_text,
                     use_colour)
from .tls import TrustError
from .types import Brand, Observation
from .watch import DEFAULT_INTERVAL, DEFAULT_RECENT, follow, scan

VERSION = "0.1.0"

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2


def build_matcher(brands: list[str], own: list[str], min_score: float) -> Matcher:
    owned = [d.strip().lower().rstrip(".") for d in own if d.strip()]
    return Matcher([Brand.build(name, owned) for name in brands],
                   min_score=min_score)


def _logs(args, wanted: int | None = None):
    logs = discover(cafile=args.cafile, timeout=args.timeout)
    if not logs:
        raise OSError("no usable transparency logs found in the published list")
    return logs[:wanted] if wanted else logs


def _emit(summary: Summary, args) -> int:
    if args.json:
        print(render_json(summary))
    else:
        colour = False if args.no_color else None
        print(render_text(summary, colour=colour, limit=args.top), end="")
    return EXIT_FOUND if summary.matches else EXIT_CLEAN


def cmd_check(args) -> int:
    """Score names given on the command line, with no network at all."""
    matcher = build_matcher(args.brand, args.own, args.min_score)
    summary = Summary(brands=tuple(sorted(matcher.brands)))
    for name in args.names:
        summary.names += 1
        found = matcher.match(Observation(name=name.strip().lower(), timestamp=0.0))
        if found is not None:
            summary.matches.append(found)
    return _emit(summary, args)


def cmd_recent(args) -> int:
    matcher = build_matcher(args.brand, args.own, args.min_score)
    logs = _logs(args, args.logs)
    live = None if args.json else _printer(args)
    summary = scan(logs, matcher, recent=args.recent, timeout=args.timeout,
                   on_match=live)
    if live:
        print()
    return _emit(summary, args)


def cmd_watch(args) -> int:
    matcher = build_matcher(args.brand, args.own, args.min_score)
    logs = _logs(args, args.logs)
    live = _printer(args) if not args.json else None

    print(f"   watching {', '.join(sorted(matcher.brands))} across "
          f"{len(logs)} logs. Control-c to stop.\n", file=sys.stderr)
    try:
        summary = follow(logs, matcher, interval=args.interval,
                         timeout=args.timeout, on_match=live)
    except KeyboardInterrupt:
        print("\n   stopped.", file=sys.stderr)
        return EXIT_CLEAN
    return _emit(summary, args)


def cmd_logs(args) -> int:
    logs = _logs(args)
    print(f"   {len(logs)} usable transparency logs covering now\n")
    for log in logs:
        print(f"   {log.operator:14} {log.name:34} {log.url}")
    return EXIT_CLEAN


def _printer(args):
    colour = use_colour() and not args.no_color
    def show(match):
        print(render_line(match, colour), flush=True)
    return show


def _menu_action(_number: int, entry) -> int | None:
    name, _blurb = entry
    if name == "Tutorial":
        print(TUTORIAL)
        return None

    if name == "Logs":
        return _guard(lambda: cmd_logs(_defaults()))

    brand = ask("Brand to watch, for example paypal")
    if not brand:
        return None
    own = [d for d in ask("Domains you own, comma separated").split(",") if d.strip()]

    args = _defaults(brand=[brand], own=own)
    if name == "Check a name":
        target = ask("Name to check")
        if not target:
            return None
        args.names = [target]
        return _guard(lambda: cmd_check(args))
    if name == "Brands":
        try:
            matcher = build_matcher(args.brand, args.own, 0.0)
        except BrandError as error:
            print(f"   {error}")
            return None
        print(f"   watching {', '.join(matcher.brands)}")
        print(f"   ignoring {', '.join(args.own) or 'nothing, which will be noisy'}")
        return None
    if name == "Recent":
        return _guard(lambda: cmd_recent(args))
    if name == "Watch":
        return _guard(lambda: cmd_watch(args))
    return None


def _guard(action) -> None:
    try:
        action()
    except (BrandError, TrustError) as error:
        print(f"   {error}")
    except (OSError, CtError) as error:
        print(f"   network error: {error}")
    except KeyboardInterrupt:
        print("\n   stopped.")
    return None


def _defaults(**overrides) -> argparse.Namespace:
    base = dict(brand=[], own=[], names=[], json=False, top=None, no_color=False,
                cafile=None, timeout=30.0, min_score=0.7, recent=DEFAULT_RECENT,
                interval=DEFAULT_INTERVAL, logs=4)
    base.update(overrides)
    return argparse.Namespace(**base)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certinator",
        description="Watch the Certificate Transparency logs for domains "
                    "impersonating a brand, at the moment their certificate "
                    "is issued.",
        epilog="Exit status: 0 nothing found, 1 impersonations reported, "
               "2 error.")
    parser.add_argument("--version", action="version",
                        version=f"certinator {VERSION}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--brand", action="append", default=[], metavar="NAME",
                        help="brand to watch for, repeatable")
    common.add_argument("--own", action="append", default=[], metavar="DOMAIN",
                        help="a domain you legitimately own, repeatable. "
                             "Without these your own certificates are reported")
    common.add_argument("--min-score", type=float, default=0.7, metavar="N",
                        help="drop findings below this score, 0 to 1 "
                             "(default 0.7, which excludes a brand merely "
                             "appearing inside a longer name)")
    common.add_argument("--all", dest="min_score", action="store_const",
                        const=0.0, help="include weak findings too")
    common.add_argument("--json", action="store_true", help="machine readable")
    common.add_argument("--top", type=int, metavar="N",
                        help="show only the N strongest findings")
    common.add_argument("--no-color", action="store_true")
    common.add_argument("--cafile", metavar="PATH",
                        help="certificate authorities to verify the log servers "
                             "against, if your Python has no trust store")
    common.add_argument("--timeout", type=float, default=30.0, metavar="SECONDS")

    subs = parser.add_subparsers(dest="command")

    watch = subs.add_parser("watch", parents=[common],
                            help="follow the logs and report as certificates appear")
    watch.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                       metavar="SECONDS", help="seconds between polls")
    watch.add_argument("--logs", type=int, default=4, metavar="N",
                       help="how many logs to follow (default 4)")
    watch.set_defaults(func=cmd_watch, names=[], recent=DEFAULT_RECENT)

    recent = subs.add_parser("recent", parents=[common],
                             help="check the most recent entries and stop")
    recent.add_argument("--recent", type=int, default=DEFAULT_RECENT,
                        metavar="N", help="entries to check per log")
    recent.add_argument("--logs", type=int, default=4, metavar="N")
    recent.set_defaults(func=cmd_recent, names=[], interval=DEFAULT_INTERVAL)

    check = subs.add_parser("check", parents=[common],
                            help="score names given here, without touching the network")
    check.add_argument("names", nargs="+", metavar="NAME")
    check.set_defaults(func=cmd_check, recent=DEFAULT_RECENT,
                       interval=DEFAULT_INTERVAL, logs=4)

    logs_cmd = subs.add_parser("logs", parents=[common],
                               help="list the transparency logs in use")
    logs_cmd.set_defaults(func=cmd_logs, names=[], recent=DEFAULT_RECENT,
                          interval=DEFAULT_INTERVAL, logs=None)

    args = parser.parse_args(argv)

    if args.command is None:
        if interactive() and argv is None:
            return run_menu("certinator", _menu_action)
        parser.print_help()
        return EXIT_ERROR

    if args.command != "logs" and not args.brand:
        parser.error("give at least one --brand")
    if not 0.0 <= args.min_score <= 1.0:
        parser.error("--min-score must be between 0 and 1")
    if args.top is not None and args.top < 1:
        parser.error("--top must be at least 1")

    try:
        return args.func(args)
    except BrandError as error:
        print(f"certinator: {error}", file=sys.stderr)
        return EXIT_ERROR
    except TrustError as error:
        print(f"certinator: {error}", file=sys.stderr)
        return EXIT_ERROR
    except (OSError, CtError) as error:
        print(f"certinator: network error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
