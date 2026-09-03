"""A minimal ASN.1 DER reader, enough to navigate a certificate.

This is not a general ASN.1 library and deliberately does not try to be. It
walks tag-length-value triples so the parts of a certificate that name a domain
can be found, and nothing more.

Certificate Transparency is a firehose of certificates issued by anyone who can
pass a domain validation check, which makes every byte here attacker
influenced. Lengths are therefore bounded before they are used, nesting depth
is capped, and a malformed structure raises DerError rather than raising
IndexError from somewhere deep in a walk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

MAX_DEPTH = 32

# Universal tags used when reading a certificate.
BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
UTF8_STRING = 0x0C
SEQUENCE = 0x30
SET = 0x31
PRINTABLE_STRING = 0x13
T61_STRING = 0x14
IA5_STRING = 0x16
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
UNIVERSAL_STRING = 0x1C
BMP_STRING = 0x1E

CLASS_CONTEXT = 0x80
CONSTRUCTED = 0x20

_TEXT_TAGS = {
    UTF8_STRING: "utf-8",
    PRINTABLE_STRING: "ascii",
    IA5_STRING: "ascii",
    T61_STRING: "latin-1",
    BMP_STRING: "utf-16-be",
    UNIVERSAL_STRING: "utf-32-be",
}


class DerError(Exception):
    """A structure was not valid DER, or was cut short."""


@dataclass(frozen=True, slots=True)
class Element:
    tag: int
    start: int      # first byte of the value
    end: int        # one past the last byte of the value
    buf: bytes

    @property
    def value(self) -> bytes:
        return self.buf[self.start:self.end]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & CONSTRUCTED)

    @property
    def tag_number(self) -> int:
        return self.tag & 0x1F

    @property
    def is_context(self) -> bool:
        return self.tag & 0xC0 == CLASS_CONTEXT

    def children(self, depth: int = 0) -> Iterator["Element"]:
        """Walk the elements inside a constructed element."""
        if not self.constructed:
            raise DerError(f"tag {self.tag:#04x} is primitive and has no children")
        if depth >= MAX_DEPTH:
            raise DerError("nesting too deep")
        offset = self.start
        while offset < self.end:
            child = parse(self.buf, offset, limit=self.end)
            yield child
            offset = child.end

    def child_list(self) -> list["Element"]:
        return list(self.children())

    def text(self) -> str:
        """Decode a string element, replacing anything undecodable.

        A name that will be compared against a brand must never fail to decode:
        an unreadable byte is a reason to look harder, not to drop the entry.
        """
        encoding = _TEXT_TAGS.get(self.tag_number if not self.is_context else -1)
        if encoding is None:
            encoding = _TEXT_TAGS.get(self.tag, "utf-8")
        try:
            return self.value.decode(encoding, "replace")
        except LookupError:
            return self.value.decode("utf-8", "replace")


def parse(buf: bytes, offset: int = 0, limit: int | None = None) -> Element:
    """Read one element at offset. limit bounds it to an enclosing element."""
    end_of_buf = len(buf) if limit is None else min(limit, len(buf))
    if offset >= end_of_buf:
        raise DerError("no element at offset")

    tag = buf[offset]
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not supported")

    cursor = offset + 1
    if cursor >= end_of_buf:
        raise DerError("truncated before length")

    first = buf[cursor]
    cursor += 1
    if first == 0x80:
        # Legal in BER, forbidden in DER, and a certificate is DER.
        raise DerError("indefinite length")
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count > 8:
            raise DerError(f"length field of {count} bytes is implausible")
        if cursor + count > end_of_buf:
            raise DerError("truncated length field")
        length = int.from_bytes(buf[cursor:cursor + count], "big")
        cursor += count

    if length > end_of_buf - cursor:
        raise DerError(f"element claims {length} bytes, {end_of_buf - cursor} remain")
    return Element(tag=tag, start=cursor, end=cursor + length, buf=buf)


def oid_string(element: Element) -> str:
    """Dotted decimal form of an OBJECT IDENTIFIER."""
    raw = element.value
    if not raw:
        raise DerError("empty object identifier")

    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for index, byte in enumerate(raw[1:], start=1):
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
        elif index == len(raw) - 1:
            raise DerError("object identifier ends mid arc")
    return ".".join(parts)


def find(parent: Element, tag: int) -> Element | None:
    for child in parent.children():
        if child.tag == tag:
            return child
    return None
