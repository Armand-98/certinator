"""MerkleTreeLeaf tests, assembled from the RFC 6962 wire format."""

import struct

import pytest

from certinator.leaf import (LeafError, MAX_CERT_BYTES, PRECERT_ENTRY,
                             X509_ENTRY, parse_leaf)


def u24(n):
    return n.to_bytes(3, "big")


def build(entry_type=X509_ENTRY, *, der=b"DERBYTES", timestamp=1_700_000_000_000,
          version=0, leaf_type=0, issuer_key_hash=b"\xaa" * 32,
          claimed_len=None, extensions=b""):
    out = bytes([version, leaf_type]) + struct.pack(">QH", timestamp, entry_type)
    if entry_type == PRECERT_ENTRY:
        out += issuer_key_hash
    out += u24(len(der) if claimed_len is None else claimed_len) + der
    return out + struct.pack(">H", len(extensions)) + extensions


def test_x509_entry():
    leaf = parse_leaf(build(X509_ENTRY, der=b"CERT", timestamp=1_700_000_000_500))
    assert leaf.entry_type == X509_ENTRY
    assert not leaf.is_precert
    assert leaf.der == b"CERT"
    assert leaf.timestamp == 1_700_000_000_500
    assert leaf.seconds == pytest.approx(1_700_000_000.5)


def test_precert_entry_skips_the_issuer_key_hash():
    """The 32 byte hash sits between the header and the TBSCertificate. Reading
    the length prefix without skipping it yields garbage."""
    leaf = parse_leaf(build(PRECERT_ENTRY, der=b"TBSCERTIFICATE"))
    assert leaf.is_precert
    assert leaf.der == b"TBSCERTIFICATE"


def test_a_precert_and_an_x509_entry_with_the_same_payload_differ():
    assert (parse_leaf(build(X509_ENTRY, der=b"SAME")).der
            == parse_leaf(build(PRECERT_ENTRY, der=b"SAME")).der)


def test_large_certificate_is_read_whole():
    body = b"\x01" * 40000
    assert parse_leaf(build(der=body)).der == body


# --- hostile input ---------------------------------------------------------

def test_absurd_length_is_refused_without_allocating():
    raw = build(der=b"", claimed_len=MAX_CERT_BYTES + 1)
    with pytest.raises(LeafError, match="refusing to read"):
        parse_leaf(raw)


def test_length_beyond_the_leaf():
    with pytest.raises(LeafError, match="remain in the leaf"):
        parse_leaf(build(der=b"short", claimed_len=9999))


def test_unsupported_version():
    with pytest.raises(LeafError, match="unsupported leaf version"):
        parse_leaf(build(version=9))


def test_unsupported_leaf_type():
    with pytest.raises(LeafError, match="unsupported leaf type"):
        parse_leaf(build(leaf_type=1))


def test_unknown_entry_type():
    with pytest.raises(LeafError, match="unknown entry type"):
        parse_leaf(build(entry_type=7))


def test_truncated_header():
    for size in range(0, 12):
        with pytest.raises(LeafError, match="shorter than"):
            parse_leaf(build()[:size])


def test_precert_cut_inside_the_issuer_key_hash():
    with pytest.raises(LeafError):
        parse_leaf(build(PRECERT_ENTRY)[:30])


def test_cut_inside_the_length_prefix():
    with pytest.raises(LeafError, match="length prefix"):
        parse_leaf(build(der=b"x")[:14])
