"""DER reader tests, from bytes assembled by hand against X.690."""

import pytest

from certinator.der import (DerError, IA5_STRING, OID, PRINTABLE_STRING,
                            SEQUENCE, UTF8_STRING, oid_string, parse)


def tlv(tag, value):
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def seq(*parts):
    return tlv(SEQUENCE, b"".join(parts))


def test_short_form_length():
    element = parse(tlv(PRINTABLE_STRING, b"hello"))
    assert element.value == b"hello"
    assert not element.constructed


def test_long_form_length():
    body = b"x" * 300
    element = parse(tlv(UTF8_STRING, body))
    assert element.value == body


def test_children_are_walked_in_order():
    raw = seq(tlv(PRINTABLE_STRING, b"a"), tlv(PRINTABLE_STRING, b"b"))
    assert [c.value for c in parse(raw).children()] == [b"a", b"b"]


def test_nested_structures():
    raw = seq(seq(tlv(PRINTABLE_STRING, b"deep")))
    inner = parse(raw).child_list()[0].child_list()[0]
    assert inner.value == b"deep"


@pytest.mark.parametrize("oid_hex,expected", [
    ("550403", "2.5.4.3"),
    ("551d11", "2.5.29.17"),
    ("2a864886f70d010101", "1.2.840.113549.1.1.1"),
    ("2b06010505070301", "1.3.6.1.5.5.7.3.1"),
])
def test_object_identifiers(oid_hex, expected):
    element = parse(tlv(OID, bytes.fromhex(oid_hex)))
    assert oid_string(element) == expected


def test_text_decoding_per_tag():
    assert parse(tlv(UTF8_STRING, "café".encode())).text() == "café"
    assert parse(tlv(IA5_STRING, b"host.example")).text() == "host.example"


def test_undecodable_bytes_are_replaced_not_raised():
    """A name that cannot be decoded is a reason to look harder, not to drop
    the certificate."""
    assert parse(tlv(UTF8_STRING, b"\xff\xfe bad")).text().endswith("bad")


# --- hostile input ---------------------------------------------------------

def test_indefinite_length_is_rejected():
    """Legal in BER, forbidden in DER, and a certificate is DER."""
    with pytest.raises(DerError, match="indefinite length"):
        parse(bytes([SEQUENCE, 0x80]) + b"\x00\x00")


def test_length_beyond_the_buffer_is_refused_without_allocating():
    with pytest.raises(DerError, match="claims 1000 bytes"):
        parse(bytes([PRINTABLE_STRING, 0x82]) + (1000).to_bytes(2, "big") + b"ab")


def test_implausible_length_field_is_refused():
    with pytest.raises(DerError, match="implausible"):
        parse(bytes([PRINTABLE_STRING, 0x8F]) + b"\x00" * 15)


def test_high_tag_numbers_are_rejected():
    with pytest.raises(DerError, match="high tag numbers"):
        parse(b"\x1f\x81\x00\x00")


def test_truncated_inputs():
    for raw in (b"", b"\x30", b"\x30\x82", b"\x30\x82\x01"):
        with pytest.raises(DerError):
            parse(raw)


def test_deep_nesting_is_capped_not_recursed():
    """A hostile entry must not be able to exhaust the stack."""
    raw = tlv(PRINTABLE_STRING, b"x")
    for _ in range(200):
        raw = seq(raw)

    def walk(element, depth=0):
        if not element.constructed:
            return depth
        return max(walk(child, depth + 1) for child in element.children(depth))

    with pytest.raises(DerError, match="too deep"):
        walk(parse(raw))


def test_a_primitive_has_no_children():
    with pytest.raises(DerError, match="primitive"):
        list(parse(tlv(PRINTABLE_STRING, b"x")).children())


def test_empty_object_identifier():
    with pytest.raises(DerError, match="empty object identifier"):
        oid_string(parse(tlv(OID, b"")))


def test_object_identifier_ending_mid_arc():
    with pytest.raises(DerError, match="mid arc"):
        oid_string(parse(tlv(OID, bytes.fromhex("5504ff"))))
