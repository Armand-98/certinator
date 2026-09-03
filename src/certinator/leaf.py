"""Decode a Certificate Transparency log entry.

A get-entries response hands back base64 of a MerkleTreeLeaf, defined in
RFC 6962 section 3.4 as TLS presentation language:

    MerkleTreeLeaf {
        Version           version;        // 1 byte
        MerkleLeafType    leaf_type;      // 1 byte, 0 = timestamped_entry
        TimestampedEntry  entry;
    }

    TimestampedEntry {
        uint64            timestamp;
        LogEntryType      entry_type;     // 2 bytes, 0 = x509, 1 = precert
        select (entry_type) {
            case x509_entry:    ASN.1Cert;              // 3 byte length
            case precert_entry: PreCert;                // 32 byte issuer key
        };                                              // hash, then TBS with
        CtExtensions      extensions;                   // a 3 byte length
    }

Precertificates are the majority of what a log carries, so handling them is not
optional. Their payload is a bare TBSCertificate rather than a full
Certificate, which is why the X.509 reader accepts both.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

X509_ENTRY = 0
PRECERT_ENTRY = 1

_TIMESTAMPED_ENTRY = 0
_ISSUER_KEY_HASH_LEN = 32

# A certificate larger than this is not a certificate.
MAX_CERT_BYTES = 1 << 21


class LeafError(Exception):
    """The leaf was not a MerkleTreeLeaf this parser understands."""


@dataclass(frozen=True, slots=True)
class Leaf:
    timestamp: int          # milliseconds since the epoch, as the log records it
    entry_type: int
    der: bytes              # Certificate for x509 entries, TBSCertificate for precerts

    @property
    def is_precert(self) -> bool:
        return self.entry_type == PRECERT_ENTRY

    @property
    def seconds(self) -> float:
        return self.timestamp / 1000.0


def parse_leaf(raw: bytes) -> Leaf:
    if len(raw) < 12:
        raise LeafError("leaf shorter than a TimestampedEntry header")

    version, leaf_type = raw[0], raw[1]
    if version != 0:
        raise LeafError(f"unsupported leaf version {version}")
    if leaf_type != _TIMESTAMPED_ENTRY:
        raise LeafError(f"unsupported leaf type {leaf_type}")

    timestamp, entry_type = struct.unpack(">QH", raw[2:12])
    offset = 12

    if entry_type == PRECERT_ENTRY:
        offset += _ISSUER_KEY_HASH_LEN
        if offset > len(raw):
            raise LeafError("leaf ends inside the issuer key hash")
    elif entry_type != X509_ENTRY:
        raise LeafError(f"unknown entry type {entry_type}")

    der, _ = _read_u24_block(raw, offset)
    return Leaf(timestamp=timestamp, entry_type=entry_type, der=der)


def _read_u24_block(raw: bytes, offset: int) -> tuple[bytes, int]:
    """Read a TLS vector with a three byte length, bounded before allocating."""
    if offset + 3 > len(raw):
        raise LeafError("leaf ends inside a length prefix")
    length = int.from_bytes(raw[offset:offset + 3], "big")
    if length > MAX_CERT_BYTES:
        raise LeafError(f"entry claims {length} bytes, refusing to read it")
    start = offset + 3
    if start + length > len(raw):
        raise LeafError(f"entry claims {length} bytes, "
                        f"{len(raw) - start} remain in the leaf")
    return raw[start:start + length], start + length
