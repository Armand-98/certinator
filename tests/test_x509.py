"""X.509 extraction tests, from certificates assembled byte by byte.

Building the structures here rather than pasting a captured certificate means a
passing test proves agreement with RFC 5280 rather than with one CA's habits.
"""

import datetime
import struct

import pytest

from certinator.der import (BIT_STRING, IA5_STRING, INTEGER, NULL, OCTET_STRING,
                            OID, PRINTABLE_STRING, SEQUENCE, SET, UTC_TIME,
                            UTF8_STRING, GENERALIZED_TIME, BOOLEAN)
from certinator.x509 import CertificateError, parse_certificate

CN = bytes.fromhex("550403")
ORG = bytes.fromhex("55040a")
SAN = bytes.fromhex("551d11")


def tlv(tag, value):
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def seq(*parts):
    return tlv(SEQUENCE, b"".join(parts))


def name(common="", org=""):
    rdns = []
    if common:
        rdns.append(tlv(SET, seq(tlv(OID, CN), tlv(UTF8_STRING, common.encode()))))
    if org:
        rdns.append(tlv(SET, seq(tlv(OID, ORG), tlv(UTF8_STRING, org.encode()))))
    return seq(*rdns)


def validity(before="240101000000Z", after="250101000000Z", tag=UTC_TIME):
    return seq(tlv(tag, before.encode()), tlv(tag, after.encode()))


def san_extension(*dns_names, critical=False):
    general = b"".join(tlv(0x82, n.encode()) for n in dns_names)
    parts = [tlv(OID, SAN)]
    if critical:
        parts.append(tlv(BOOLEAN, b"\xff"))
    parts.append(tlv(OCTET_STRING, seq(general)))
    return seq(*parts)


def tbs(*, subject_cn="", issuer_cn="", version=True, extensions=(),
        serial=b"\x01\x02\x03", valid=None):
    parts = []
    if version:
        parts.append(tlv(0xA0, tlv(INTEGER, b"\x02")))
    parts.append(tlv(INTEGER, serial))
    parts.append(seq(tlv(OID, bytes.fromhex("2a864886f70d01010b")), tlv(NULL, b"")))
    parts.append(name(issuer_cn))
    parts.append(valid or validity())
    parts.append(name(subject_cn))
    parts.append(seq(seq(tlv(OID, bytes.fromhex("2a864886f70d010101")),
                         tlv(NULL, b"")), tlv(BIT_STRING, b"\x00key")))
    if extensions:
        parts.append(tlv(0xA3, seq(*extensions)))
    return seq(*parts)


def certificate(**kw):
    return seq(tbs(**kw),
               seq(tlv(OID, bytes.fromhex("2a864886f70d01010b")), tlv(NULL, b"")),
               tlv(BIT_STRING, b"\x00sig"))


# --- the two shapes a CT log carries ---------------------------------------

def test_full_certificate():
    cert = parse_certificate(certificate(subject_cn="example.com",
                                         issuer_cn="Test CA"))
    assert cert.common_name == "example.com"
    assert cert.issuer == "Test CA"


def test_bare_tbscertificate_from_a_precert_entry():
    """Precertificates are the majority of a log's entries and carry a
    TBSCertificate with no Certificate wrapper around it."""
    cert = parse_certificate(tbs(subject_cn="precert.example",
                                 issuer_cn="Test CA"))
    assert cert.common_name == "precert.example"
    assert cert.issuer == "Test CA"


def test_version_field_is_optional_and_shifts_everything():
    """A v1 certificate omits the version, so every later field moves up one."""
    cert = parse_certificate(tbs(subject_cn="v1.example", version=False))
    assert cert.common_name == "v1.example"


# --- names -----------------------------------------------------------------

def test_subject_alt_names():
    cert = parse_certificate(certificate(
        subject_cn="example.com",
        extensions=(san_extension("example.com", "www.example.com",
                                  "*.api.example.com"),)))
    assert cert.dns_names == ("example.com", "www.example.com", "*.api.example.com")


def test_names_merges_common_name_and_alt_names_without_duplicates():
    cert = parse_certificate(certificate(
        subject_cn="Example.COM",
        extensions=(san_extension("example.com", "www.example.com"),)))
    assert cert.names == ("example.com", "www.example.com")


def test_a_trailing_dot_is_not_a_different_host():
    cert = parse_certificate(certificate(subject_cn="example.com."))
    assert cert.names == ("example.com",)


def test_critical_flag_between_the_oid_and_the_value():
    """The optional critical BOOLEAN sits between them, so a positional read of
    the extension value is wrong."""
    cert = parse_certificate(certificate(
        extensions=(san_extension("crit.example", critical=True),)))
    assert cert.dns_names == ("crit.example",)


def test_alt_names_found_past_an_unrelated_extension():
    other = seq(tlv(OID, bytes.fromhex("551d0f")), tlv(OCTET_STRING, b"\x03\x02\x01\x06"))
    cert = parse_certificate(certificate(
        extensions=(other, san_extension("late.example"))))
    assert cert.dns_names == ("late.example",)


def test_non_dns_general_names_are_ignored():
    """A SAN may hold email, IP and URI entries; only dNSName names a host."""
    general = (tlv(0x81, b"admin@example.com")      # rfc822Name
               + tlv(0x82, b"real.example")         # dNSName
               + tlv(0x87, bytes([192, 0, 2, 1])))  # iPAddress
    extension = seq(tlv(OID, SAN), tlv(OCTET_STRING, seq(general)))
    cert = parse_certificate(certificate(extensions=(extension,)))
    assert cert.dns_names == ("real.example",)


def test_certificate_with_no_extensions():
    cert = parse_certificate(certificate(subject_cn="bare.example"))
    assert cert.dns_names == ()
    assert cert.names == ("bare.example",)


def test_issuer_falls_back_to_organisation():
    tbs_bytes = seq(
        tlv(0xA0, tlv(INTEGER, b"\x02")),
        tlv(INTEGER, b"\x01"),
        seq(tlv(OID, bytes.fromhex("2a864886f70d01010b")), tlv(NULL, b"")),
        name(org="Some Authority Ltd"),
        validity(),
        name("subject.example"),
        seq(seq(tlv(OID, bytes.fromhex("2a864886f70d010101")), tlv(NULL, b"")),
            tlv(BIT_STRING, b"\x00key")),
    )
    assert parse_certificate(tbs_bytes).issuer == "Some Authority Ltd"


# --- validity --------------------------------------------------------------

def test_utctime_pivots_at_fifty():
    cert = parse_certificate(certificate(valid=validity("490101000000Z",
                                                        "500101000000Z")))
    assert cert.not_before.year == 2049
    assert cert.not_after.year == 1950


def test_generalizedtime_has_four_digit_years():
    cert = parse_certificate(certificate(
        valid=validity("20240301120000Z", "20260301120000Z", tag=GENERALIZED_TIME)))
    assert cert.not_before == datetime.datetime(2024, 3, 1, 12, 0,
                                                tzinfo=datetime.timezone.utc)
    assert cert.not_after.year == 2026


def test_unparseable_time_is_none_not_an_exception():
    cert = parse_certificate(certificate(valid=validity("garbage", "alsobad")))
    assert cert.not_before is None and cert.not_after is None


# --- hostile input ---------------------------------------------------------

def test_not_a_sequence():
    with pytest.raises(CertificateError):
        parse_certificate(tlv(INTEGER, b"\x01"))


def test_truncated_certificate():
    with pytest.raises(CertificateError):
        parse_certificate(certificate(subject_cn="example.com")[:20])


def test_tbs_that_ends_before_the_subject():
    with pytest.raises(CertificateError, match="ends before the subject"):
        parse_certificate(seq(tlv(INTEGER, b"\x01")))


def test_empty_sequence():
    with pytest.raises(CertificateError, match="empty"):
        parse_certificate(seq())


def test_garbage_inside_the_san_extension_is_survived():
    extension = seq(tlv(OID, SAN), tlv(OCTET_STRING, b"\xff\xff\xff"))
    cert = parse_certificate(certificate(subject_cn="ok.example",
                                         extensions=(extension,)))
    assert cert.names == ("ok.example",)
