"""TLS trust for outbound requests.

Certificate Transparency is fetched over HTTPS, and a tool whose subject is
certificates has no business skipping certificate verification. Verification is
therefore never disabled, and there is no flag to disable it.

The complication is that a Python installed from python.org ships no trust
store at all: ssl.create_default_context() returns a context with zero
certificates loaded, and every request fails with an unhelpful "unable to get
local issuer certificate". Rather than tell the user to go run a shell script,
the system bundle is located and used.
"""

from __future__ import annotations

import ssl
from pathlib import Path

# Ordered by how likely each is to be current, most maintained first.
SYSTEM_BUNDLES = (
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/ca-certificates/cert.pem",
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",      # Debian, Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",        # Fedora, RHEL
    "/etc/ssl/ca-bundle.pem",                  # SUSE
)


class TrustError(Exception):
    """No certificate authorities could be found to verify anything against."""


def find_bundle() -> str | None:
    for candidate in SYSTEM_BUNDLES:
        if Path(candidate).is_file():
            return candidate
    return None


def context(cafile: str | None = None) -> ssl.SSLContext:
    """An SSL context that verifies, whatever the interpreter was built with."""
    if cafile:
        ctx = ssl.create_default_context(cafile=cafile)
        if not ctx.get_ca_certs():
            raise TrustError(f"{cafile} contains no certificate authorities")
        return ctx

    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx

    bundle = find_bundle()
    if bundle is None:
        raise TrustError(
            "this Python has no trust store and no system CA bundle was found. "
            "Pass --cafile with the path to one, or on macOS run "
            "'Install Certificates.command' from your Python installation.")
    ctx = ssl.create_default_context(cafile=bundle)
    if not ctx.get_ca_certs():
        raise TrustError(f"{bundle} contains no certificate authorities")
    return ctx
