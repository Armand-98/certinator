#!/usr/bin/env python3
"""Measure the matcher against a labelled corpus.

Every name here is labelled by hand, which is the honest limitation of this
number: it measures the matcher against one person's idea of what
impersonation looks like. The external check is running against the live logs,
where the names were not chosen by anyone.

    ./.venv/bin/python tools/evaluate.py
    ./.venv/bin/python tools/evaluate.py --markdown
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from certinator.match import Matcher                     # noqa: E402
from certinator.types import (BITSQUAT, COMBOSQUAT, HOMOGRAPH,  # noqa: E402
                              SUBDOMAIN, TLDSQUAT, TYPO, Brand, Observation)

BRANDS = [
    Brand.build("paypal", ["paypal.com", "paypal.co.uk", "paypalobjects.com"]),
    Brand.build("netflix", ["netflix.com", "nflxvideo.net"]),
    Brand.build("coinbase", ["coinbase.com"]),
]

# (name, expected technique). These are the shapes real phishing registrations
# take, written out rather than harvested, so each is checkable by eye.
IMPERSONATIONS = [
    ("рaypal.com", HOMOGRAPH),         # Cyrillic er
    ("paуpal.com", HOMOGRAPH),         # Cyrillic u
    ("paypa1.com", HOMOGRAPH),              # digit one for l
    ("c0inbase.com", HOMOGRAPH),            # zero for o
    ("netf1ix.com", HOMOGRAPH),
    ("paypal.xyz", TLDSQUAT),
    ("netflix.top", TLDSQUAT),
    ("coinbase.help", TLDSQUAT),
    ("paypal.com.account-verify.example", SUBDOMAIN),
    ("netflix.com.billing-update.example", SUBDOMAIN),
    ("coinbase.com.wallet-restore.example", SUBDOMAIN),
    ("paypall.com", TYPO),
    ("paypl.net", TYPO),
    ("apypal.org", TYPO),
    ("netflixx.com", TYPO),
    ("netlfix.com", TYPO),
    ("coinbse.com", TYPO),
    ("paypal-login.com", COMBOSQUAT),
    ("secure-paypal.net", COMBOSQUAT),
    ("netflix-billing.com", COMBOSQUAT),
    ("coinbase-wallet-verify.com", COMBOSQUAT),
    ("my-coinbase-account.net", COMBOSQUAT),
]

# Must never be reported at the default threshold.
LEGITIMATE = [
    "paypal.com", "www.paypal.com", "api.paypal.com", "a.b.c.paypal.com",
    "paypal.co.uk", "www.paypal.co.uk", "paypalobjects.com",
    "cdn.paypalobjects.com",
    "netflix.com", "www.netflix.com", "ipv4-c001.nflxvideo.net",
    "coinbase.com", "assets.coinbase.com",
    "github.com", "stripe.com", "cloudflare.com", "example.org",
    "mail.google.com", "s3.amazonaws.com", "kubernetes.default.svc",
    "some-unrelated-startup.io", "a.very.deep.subdomain.example.net",
    # A brand inside a longer name with no other signal. Live traffic is full
    # of these and they are somebody's own infrastructure far more often than
    # they are an attack, which is why they sit below the default threshold.
    "microsoft-falcon.net", "paypalace-restaurant.com", "netflixandchill.dev",
]

DEFAULT_THRESHOLD = 0.7


def evaluate(threshold: float):
    matcher = Matcher(BRANDS, min_score=threshold)
    caught, missed, wrong_technique = [], [], []
    for name, expected in IMPERSONATIONS:
        found = matcher.match(Observation(name=name, timestamp=0.0))
        if found is None:
            missed.append((name, expected))
        elif found.technique != expected:
            wrong_technique.append((name, expected, found.technique))
            caught.append(name)
        else:
            caught.append(name)

    false_positives = []
    for name in LEGITIMATE:
        found = matcher.match(Observation(name=name, timestamp=0.0))
        if found is not None:
            false_positives.append((name, found.technique, found.score))
    return caught, missed, wrong_technique, false_positives


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()

    caught, missed, wrong, fps = evaluate(args.threshold)
    total = len(IMPERSONATIONS)
    recall = len(caught) / total

    if args.markdown:
        print(f"Measured at the default threshold of {args.threshold}, "
              f"{total} impersonations and {len(LEGITIMATE)} legitimate names.\n")
        print("| | Count |")
        print("|---|---|")
        print(f"| Impersonations detected | {len(caught)}/{total} |")
        print(f"| Missed | {len(missed)} |")
        print(f"| Misclassified technique | {len(wrong)} |")
        print(f"| False positives on legitimate names | {len(fps)}/{len(LEGITIMATE)} |")
        print(f"\nDetection {recall:.0%}, {len(fps)} false positives.")
    else:
        print(f"certinator evaluation, threshold {args.threshold}")
        print("=" * 64)
        print(f"  impersonations detected  {len(caught)}/{total} ({recall:.0%})")
        for name, expected in missed:
            print(f"     MISS  {name}  expected {expected}")
        for name, expected, got in wrong:
            print(f"     TECH  {name}  expected {expected}, got {got}")
        print(f"  false positives          {len(fps)}/{len(LEGITIMATE)}")
        for name, technique, score in fps:
            print(f"     FP    {name}  {technique} {score:.2f}")
        print("=" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
