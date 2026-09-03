# certinator

Watches the public Certificate Transparency logs and reports domains
impersonating a brand, at the moment their certificate is issued.

A phishing site needs a certificate before it can serve HTTPS, and it usually
gets one days before the campaign starts. That gap is the point: you find the
domain while it is still being built.

**No third-party dependencies.** The ASN.1 DER reader, the X.509 name
extraction and the RFC 6962 log-entry decoder are written from the
specifications. No `cryptography`, no OpenSSL binding, no `requests`, no
`idna`, no `tldextract`. Python 3.10+ standard library only.

## Measured results

Two numbers, measuring two different things.

**Recall, against a labelled corpus.** 22 names in the shapes real phishing
registrations take, plus 25 legitimate names including the brands' own
subdomains, alternate TLDs they own, unrelated domains, and names that merely
contain a brand. Reproduce with `python tools/evaluate.py`.

| | |
|---|---|
| Impersonations detected | **22/22** |
| Misclassified technique | 0 |
| False positives on legitimate names | **0/25** |

The honest limit of that number: the corpus is written by hand, so it measures
the matcher against one person's idea of what impersonation looks like.

**Against the live logs**, where nobody chose the names. 15 heavily targeted
brands, four logs, one pass:

| | |
|---|---|
| Log entries read | 48,000 |
| Certificate names checked | **88,784** |
| Findings | 6 |
| Genuine impersonation registrations | **5** |
| False positives | **1** |

Every certificate found had been issued in the preceding 40 minutes, which is
the point of the tool: these domains were caught while they were still being
set up.

```
[HIGH] backup04.wellsfargo.comgmail.com
       wellsfargo is a label beneath comgmail.com
[HIGH] 8528reerohghuiteceek.stadium.011dyohthoquuoshushi.wellsfargo.finacial.com
       wellsfargo is a label beneath finacial.com
[HIGH] join.bede.telegram.vpncustomize.www.speedtest.net.abrha.co.za
       telegram is a label beneath abrha.co.za
[HIGH] api.whatsapp.luckylab.my.id
       whatsapp is a label beneath luckylab.my.id
[HIGH] notexistsvpn2x.ronlox.com
       ronlox is one edit from roblox
```

`comgmail.com` and `finacial.com` are built to be misread: the first so a URL
reads `...wellsfargo.com...`, the second as a misspelling of `financial`. Both,
and `ronlox.com`, resolve to domain-parking nameservers, so what is confirmed is
that they are impersonation registrations, not that they are currently serving
phishing pages. That is the normal state of a domain caught this early.

The sixth finding, `titusapi-devfoo-federation.us-east-1.test.netflix.net`, is a
false positive and an instructive one. `netflix.net` really is Netflix's, and
Titus is their own container platform, but the run declared `netflix.com`,
`nflxvideo.net` and `nflximg.net` and not `netflix.net`. Nothing in a
certificate says who owns a domain, so an incomplete `--own` list is the one
false-positive class this design cannot remove.

## Quick start## Quick start

```bash
python -m venv .venv
./.venv/bin/pip install -e ".[dev]"

# optional: callable from anywhere, as certinator or certi
tools/install.sh                    # links into /opt/homebrew/bin

# run with no arguments for a menu, or use the flags below
certinator

# score names without touching the network
certi check --brand paypal --own paypal.com paypa1.com paypal.com.login.example

# what was issued in the last few minutes
certi recent --brand acme --own acme.com

# keep watching
certi watch --brand acme --own acme.com --own acme.co.uk
```

Exit status is `0` for nothing found, `1` when impersonations are reported, `2`
on error.

**Declare the domains you own.** Without `--own`, your own certificate renewals
are reported as impersonations and you switch the tool off in a week.

## What it looks for

| Technique | What it catches | Severity |
|---|---|---|
| `homograph` | characters that are not Latin but read as it, so `paypal` with a Cyrillic а | critical |
| `tldsquat` | the brand exactly, under a domain it does not own | high |
| `subdomain` | the brand as a label beneath someone else's domain, as in `paypal.com.secure-login.example` | high |
| `bitsquat` | one flipped bit from the brand | high |
| `typo` | one edit away: dropped, doubled, swapped or mistyped | high |
| `combosquat` | the brand beside a word like `login`, `verify` or `secure` | medium |
| `contains` | the brand embedded, with no other signal | low, off by default |

The edit neighbourhood of each brand is generated once at startup and matched
by hash lookup, so the common case is a set membership test rather than a
distance computation. `paypal` expands to 481 edit-neighbours and 26 bit-flips.
This has to keep up with every certificate issued on the internet.

## How it works

```
tls.py       verification is never disabled, and there is no flag to disable it
ctlog.py     log discovery from the published v3 list, get-sth, paged get-entries
leaf.py      RFC 6962 MerkleTreeLeaf, including precertificates
der.py       ASN.1 DER walking, hostile-input hardened
x509.py      subject CN and every dNSName in the subjectAltName extension
names.py     IDN decoding, Unicode confusable folding, registrable domain
suffixes.py  the Public Suffix List, vendored and regenerable
match.py     the six techniques above
watch.py     scan once, or follow the logs with resumable positions
report.py    ranked findings, terminal and JSON
```

## Design decisions

**Certificates are untrusted input.** These logs carry certificates issued to
anyone who can pass a domain validation check, so every byte is attacker
influenced. Every length is bounded before it is used to allocate, nesting
depth is capped, and a malformed structure is counted and skipped rather than
being fatal. A monitor that stops at the first surprise monitors nothing.

**Ownership is checked before folding, not after.** This was a real bug, and
the worst one this tool could have. Confusable folding is what makes a
homograph resemble the real domain, so testing ownership against the folded
skeleton meant `рaypal.com` with a Cyrillic р folded into `paypal.com`, matched
the owned-domain list, and was silently discarded. The single thing the tool
exists to catch was the single thing it threw away. Ownership is now tested
against the name as written, and whether folding was *required* is what
separates a homograph from a domain merely registered under another suffix.

**A capital I is a typo, not a homograph.** `paypaI.com` looks identical to
`paypal.com` in many fonts, but DNS is case-insensitive, so the domain that got
registered really is `paypai.com`. There is no disguise to see through.

**Findings collapse onto domains, not hostnames.** One certificate routinely
covers dozens of hosts under one domain and services renew weekly. The count of
what was collapsed is always reported, never hidden.

**A brand merely appearing inside a longer name is not evidence.** `contains`
is below the default threshold, because live traffic proved the point:
`microsoft-falcon.net` is Microsoft's own infrastructure and produced hundreds
of matches in a single scan. Use `--all` to include weak findings.

## Limitations

Stated because a detector without known limits has not been tested properly.

- **A brand that is also an ordinary word will match ordinary domains**, and no
  scoring fixes that. Brands under four characters are refused outright.
- **A certificate is not a phishing site.** It is somebody preparing something.
  Check what the domain serves before acting.
- **Only what is issued while you watch.** A brand is watched from the moment
  you start; certificates issued earlier are not in the window.
- **Domains a brand owns but has not declared** are reported. There is no way
  to know that `microsoft-falcon.net` is Microsoft's except by being told.
- **Combosquatting depends on a keyword list**, so `paypal-recompense.net`
  passes unless `recompense` is in it.
- **A name that folds to the brand only through an unlisted confusable** is
  missed. The folding table is built deliberately rather than shipping the full
  Unicode confusables file, which trades coverage for reviewability.
- **Not every certificate reaches every log**, so following four logs sees less
  than following all of them.

## Development

```bash
./.venv/bin/python -m pytest        # 415 tests, no network required
python tools/build_suffixes.py     # refresh the vendored Public Suffix List
```

Tests are built from bytes assembled by hand against X.690, RFC 5280 and
RFC 6962 rather than from captured samples, so a pass means agreement with the
specification rather than with one authority's habits. No test touches the
network.

## License

MIT
