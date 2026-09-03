"""Pull the names out of an X.509 certificate.

Only what identifies a domain is extracted: the subject common name, every
dNSName in the subjectAltName extension, the validity window and the issuer.
Nothing is verified. Certificate Transparency has already established that a
certificate was issued; the question here is who it was issued for.

The structure walked is RFC 5280:

    Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    TBSCertificate  ::= SEQUENCE { [0] version DEFAULT v1, serialNumber,
                                   signature, issuer, validity, subject,
                                   subjectPublicKeyInfo, ... [3] extensions }

A precertificate entry in a CT log carries a bare TBSCertificate rather than a
whole Certificate, and precertificates are the majority of what a log holds, so
both shapes are accepted.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from .der import (BIT_STRING, DerError, Element, GENERALIZED_TIME, OCTET_STRING,
                  SEQUENCE, UTC_TIME, oid_string, parse)

OID_COMMON_NAME = "2.5.4.3"
OID_ORGANISATION = "2.5.4.10"
OID_SUBJECT_ALT_NAME = "2.5.29.17"

# GeneralName ::= CHOICE { ... dNSName [2] IA5String ... }
TAG_DNS_NAME = 0x82

CONTEXT_VERSION = 0xA0
CONTEXT_EXTENSIONS = 0xA3

# No certificate names this many hosts; the cap stops one hostile entry from
# turning into unbounded work downstream.
MAX_NAMES = 4096


class CertificateError(Exception):
    """The certificate could not be read far enough to name anything."""


@dataclass(frozen=True, slots=True)
class Certificate:
    common_name: str = ""
    dns_names: tuple[str, ...] = ()
    issuer: str = ""
    not_before: datetime.datetime | None = None
    not_after: datetime.datetime | None = None
    serial: str = ""

    @property
    def names(self) -> tuple[str, ...]:
        """Every distinct name this certificate is valid for, lowercased.

        The common name is included because a certificate may still carry a
        name there that never made it into the alternative names, and a name
        that identifies the site is worth matching wherever it was written.
        """
        seen, out = set(), []
        for name in (self.common_name, *self.dns_names):
            cleaned = name.strip().rstrip(".").lower()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                out.append(cleaned)
        return tuple(out)


def parse_certificate(der: bytes) -> Certificate:
    """Read either a Certificate or a bare TBSCertificate."""
    try:
        outer = parse(der)
        if outer.tag != SEQUENCE:
            raise CertificateError("not a SEQUENCE")
        tbs = _tbs_of(outer)
        return _read_tbs(tbs)
    except DerError as error:
        raise CertificateError(str(error)) from error


def _tbs_of(outer: Element) -> Element:
    """Unwrap a Certificate, or accept a TBSCertificate as it stands.

    A Certificate is exactly three elements ending in the signature BIT STRING.
    A TBSCertificate has more, and never ends in one.
    """
    children = outer.child_list()
    if len(children) == 3 and children[2].tag == BIT_STRING:
        if children[0].tag != SEQUENCE:
            raise CertificateError("first element of a Certificate is not a SEQUENCE")
        return children[0]
    return outer


def _read_tbs(tbs: Element) -> Certificate:
    fields = tbs.child_list()
    if not fields:
        raise CertificateError("empty TBSCertificate")

    # The version field is optional, and everything after it shifts by one.
    index = 1 if fields[0].tag == CONTEXT_VERSION else 0
    if len(fields) < index + 6:
        raise CertificateError("TBSCertificate ends before the subject")

    serial = fields[index]
    issuer = fields[index + 2]
    validity = fields[index + 3]
    subject = fields[index + 4]

    extensions = None
    for candidate in fields[index + 5:]:
        if candidate.tag == CONTEXT_EXTENSIONS:
            extensions = candidate
            break

    not_before, not_after = _read_validity(validity)
    return Certificate(
        common_name=_attribute(subject, OID_COMMON_NAME),
        dns_names=_read_alt_names(extensions),
        issuer=(_attribute(issuer, OID_COMMON_NAME)
                or _attribute(issuer, OID_ORGANISATION)),
        not_before=not_before,
        not_after=not_after,
        serial=serial.value.hex(),
    )


def _attribute(name: Element, wanted: str) -> str:
    """First value of an attribute in an RDNSequence.

    Name ::= SEQUENCE OF SET OF SEQUENCE { type OBJECT IDENTIFIER, value ANY }
    """
    if not name.constructed:
        return ""
    for rdn in name.children():
        if not rdn.constructed:
            continue
        for attribute in rdn.children():
            if not attribute.constructed:
                continue
            parts = attribute.child_list()
            if len(parts) < 2:
                continue
            try:
                if oid_string(parts[0]) == wanted:
                    return parts[1].text()
            except DerError:
                continue
    return ""


def _read_alt_names(extensions: Element | None) -> tuple[str, ...]:
    if extensions is None:
        return ()
    for wrapper in extensions.children():
        if not wrapper.constructed:
            continue
        for extension in wrapper.children():
            parts = extension.child_list()
            if len(parts) < 2:
                continue
            try:
                if oid_string(parts[0]) != OID_SUBJECT_ALT_NAME:
                    continue
            except DerError:
                continue
            # extnValue is an OCTET STRING wrapping the real DER, and the
            # optional critical BOOLEAN may sit between it and the OID.
            payload = next((p for p in parts[1:] if p.tag == OCTET_STRING), None)
            if payload is None:
                continue
            return _dns_names(payload.value)
    return ()


def _dns_names(der: bytes) -> tuple[str, ...]:
    try:
        names = parse(der)
        if not names.constructed:
            return ()
        found = []
        for entry in names.children():
            if entry.tag == TAG_DNS_NAME:
                found.append(entry.value.decode("ascii", "replace"))
                if len(found) >= MAX_NAMES:
                    break
        return tuple(found)
    except DerError:
        return ()


def _read_validity(validity: Element) -> tuple[datetime.datetime | None,
                                               datetime.datetime | None]:
    if not validity.constructed:
        return None, None
    times = validity.child_list()
    if len(times) < 2:
        return None, None
    return _read_time(times[0]), _read_time(times[1])


def _read_time(element: Element) -> datetime.datetime | None:
    text = element.value.decode("ascii", "replace").strip()
    if not text.endswith("Z"):
        return None
    body = text[:-1]
    try:
        if element.tag == UTC_TIME and len(body) >= 10:
            # Two digit years, with the RFC 5280 pivot at 50.
            year = int(body[:2])
            year += 2000 if year < 50 else 1900
            rest = body[2:]
        elif element.tag == GENERALIZED_TIME and len(body) >= 12:
            year, rest = int(body[:4]), body[4:]
        else:
            return None
        month, day, hour, minute = (int(rest[0:2]), int(rest[2:4]),
                                    int(rest[4:6]), int(rest[6:8]))
        second = int(rest[8:10]) if len(rest) >= 10 else 0
        return datetime.datetime(year, month, day, hour, minute, second,
                                 tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
