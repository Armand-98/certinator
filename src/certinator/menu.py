"""Interactive menu shown when the tool is run with no arguments.

The flags are the real interface and every entry here routes to them. The menu
exists so the tool is usable by someone who has a brand to protect rather than
a workflow to automate.

Nothing here runs unless stdin and stdout are both terminals, so a pipeline
still fails fast on a missing argument instead of hanging on a prompt nobody is
there to answer.
"""

from __future__ import annotations

import sys

BRAND = "LyfieldCreationsOS"

ENTRIES = (
    ("Watch", "follow the logs live for your brands"),
    ("Recent", "check what was issued in the last few minutes"),
    ("Check a name", "score one name against a brand"),
    ("Brands", "show the brands being watched"),
    ("Logs", "list the transparency logs in use"),
    ("Tutorial", "how to use this tool"),
    ("Quit", ""),
)


def banner(title: str) -> str:
    label = f"   {title.upper()}  ·  {BRAND}   "
    rule = "═" * len(label)
    return f"  ╔{rule}╗\n  ║{label}║\n  ╚{rule}╝"


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def ask(prompt: str, default: str = "") -> str:
    shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
    try:
        answer = input(f"   {shown}").strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    return answer or default


def run(title: str, dispatch) -> int:
    """Loop the menu, handing (index, entry) to dispatch until the user quits.

    dispatch returns an exit status to stop on, or None to show the menu again.
    """
    while True:
        print()
        print(banner(title))
        for number, (name, blurb) in enumerate(ENTRIES, start=1):
            print(f"   {number}) {name:<16}{blurb}".rstrip())
        print()
        try:
            choice = input(f"   Pick 1-{len(ENTRIES)}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n   Done. See you next time.")
            return 0
        print()

        if choice in ("", "q", str(len(ENTRIES))):
            print("   Done. See you next time.")
            return 0
        if not choice.isdigit() or not 1 <= int(choice) <= len(ENTRIES):
            print(f"   Please type a number from 1 to {len(ENTRIES)}.")
            continue

        status = dispatch(int(choice), ENTRIES[int(choice) - 1])
        if status is not None:
            return status


TUTORIAL = """\
   certinator watches the public Certificate Transparency logs and tells you
   when somebody gets a certificate for a domain pretending to be yours.

   Every certificate issued on the internet is published to these logs. A
   phishing site needs a certificate before it can serve HTTPS, and it usually
   gets one days before the campaign starts. That gap is the point of this
   tool: you find the domain while it is still being built.

   Give it a brand and the domains you actually own:

     certi watch --brand paypal --own paypal.com --own paypal.co.uk

   The domains you own matter. Without them your own certificate renewals are
   reported as impersonations, and you switch the tool off in a week.

   Other ways to run it:
     certi recent --brand acme --own acme.com    what was issued just now
     certi check paypa1.com --brand paypal       score one name
     certi watch --brand acme --own acme.com --json    for a script

   What it looks for:
     homograph    characters that are not Latin but read as it, so paypal
                  spelled with a Cyrillic a. Nobody does this by accident.
     tldsquat     your brand exactly, under a domain you do not own
     subdomain    your brand as a label under someone else's domain, as in
                  paypal.com.secure-login.example
     typo         one edit away: a dropped, doubled or mistyped character
     bitsquat     one flipped bit away
     combosquat   your brand beside a word like login, verify or secure

   Two things worth knowing:

   A brand that is also an ordinary word will match ordinary domains, and no
   scoring fixes that. Brands under four characters are refused outright.

   A certificate is not a phishing site. It is somebody preparing something.
   Check what the domain actually serves before you act on it.
"""
