"""A client for the Certificate Transparency HTTP API of RFC 6962.

Three facts about real logs shape everything here.

A log returns fewer entries than asked for, without saying so: a request for
0..999 is commonly answered with 32. A client that advances its cursor by what
it requested skips the rest of the batch silently and never notices, so the
cursor here only ever advances by entries actually received.

A log rate limits. 429 and 503 are routine rather than exceptional, so they are
retried with exponential backoff, a Retry-After header is honoured when the
operator sends one, and the attempts are capped so a busy log is left alone
rather than hammered.

A log is a public server handing back attacker influenced bytes, so every
response is read under a byte cap, every field is type checked before use, and
a malformed entry truncates the batch rather than being skipped, which would
silently shift every index after it.

The set of live logs is discovered, never hardcoded. Logs are sharded by
certificate expiry and retired yearly, so a hardcoded list is precisely why
tools like this stop working a year after they are written.
"""

from __future__ import annotations

import base64
import email.utils
import http.client
import json
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

from . import tls
from .leaf import MAX_CERT_BYTES

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# Operators ask that a client identify itself so they can find whoever is
# misbehaving without blocking a whole address range.
USER_AGENT = "certinator/0.1 (+https://github.com/Armand-98/certinator)"

# Per response caps. A log that answers with gigabytes gets a CtError, not the
# whole thing in memory.
MAX_LOG_LIST_BYTES = 8 << 20
MAX_STH_BYTES = 1 << 16
MAX_ENTRIES_BYTES = 32 << 20
MAX_ENTRY_BYTES = 4 * MAX_CERT_BYTES        # one leaf_input or one extra_data

# The largest window to ask for in one get-entries call. Logs cap this far
# lower themselves; asking for more only wastes a round trip.
MAX_BATCH = 1000

RETRY_STATUS = frozenset({429, 502, 503, 504})
MAX_ATTEMPTS = 5
BACKOFF_BASE = 1.0
MAX_BACKOFF = 30.0
MAX_RETRY_AFTER = 120.0

_sleep = time.sleep


class CtError(Exception):
    """A log could not be reached, or answered with something unusable."""


class HttpError(CtError):
    """The log answered with an HTTP error status."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True, slots=True)
class Log:
    """One usable log, as the log list describes it.

    The trust configuration travels with the log because tree_size() and
    fetch() take a Log and nothing else; a log discovered with a given CA
    bundle keeps being read with that bundle.

    No tree size is stored: it is a live value on the server that is stale the
    moment it is copied, so it is asked for when it is needed.
    """

    name: str
    url: str
    operator: str = ""
    cafile: str | None = None


def discover(*, cafile: str | None = None, timeout: float = 30) -> list[Log]:
    """Every log that is usable now and covers now in its temporal interval.

    Logs are sharded by the expiry of the certificates they accept, so roughly
    half the usable logs at any moment are not accepting current issuance.
    """
    payload = _json(_get(LOG_LIST_URL, timeout=timeout, cafile=cafile,
                         limit=MAX_LOG_LIST_BYTES), "log list")
    if not isinstance(payload, dict):
        raise CtError("log list is not a JSON object")

    now = datetime.now(timezone.utc)
    logs: list[Log] = []
    for operator in _items(payload.get("operators")):
        if not isinstance(operator, dict):
            continue
        name = operator.get("name")
        for entry in _items(operator.get("logs")):
            log = _usable(entry, name if isinstance(name, str) else "", now, cafile)
            if log is not None:
                logs.append(log)
    return logs


def tree_size(log: Log, *, timeout: float = 30) -> int:
    """The number of entries in the log, from get-sth."""
    payload = _json(_get(_endpoint(log, "get-sth"), timeout=timeout,
                         cafile=log.cafile, limit=MAX_STH_BYTES), "get-sth")
    size = payload.get("tree_size") if isinstance(payload, dict) else None
    # bool is an int, and a float tree size means the log is not answering the
    # question that was asked.
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise CtError(f"{log.name}: get-sth returned no usable tree_size")
    return size


def fetch(log: Log, start: int, end: int, *,
          timeout: float = 30) -> list[tuple[int, bytes, bytes]]:
    """One get-entries call: (index, leaf_input, extra_data), base64 decoded.

    Both bounds are inclusive, as RFC 6962 defines them. The list may be
    shorter than the window requested, and an empty list means the log gave
    nothing back for a range it considers valid.
    """
    if start < 0:
        raise ValueError("start must not be negative")
    if end < start:
        raise ValueError("end must not precede start")
    end = min(end, start + MAX_BATCH - 1)

    query = urllib.parse.urlencode({"start": start, "end": end})
    url = f"{_endpoint(log, 'get-entries')}?{query}"
    try:
        raw = _get(url, timeout=timeout, cafile=log.cafile, limit=MAX_ENTRIES_BYTES)
    except HttpError as err:
        # A start past the tree head is answered with 400. That is the normal
        # way to learn a caller has caught up, not a failure.
        if err.status == 400:
            return []
        raise

    payload = _json(raw, "get-entries")
    rows = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise CtError(f"{log.name}: get-entries returned no entries array")

    out: list[tuple[int, bytes, bytes]] = []
    # A log answering with more than was asked for does not get to make the
    # caller allocate for it.
    for offset, row in enumerate(rows[:end - start + 1]):
        decoded = _entry(row)
        if decoded is None:
            # Truncate rather than skip: indices are positional, so dropping a
            # row would misattribute every entry after it.
            break
        out.append((start + offset, decoded[0], decoded[1]))
    if rows and not out:
        # An empty list means caught up, and paging stops on it. A batch
        # truncated to nothing by a bad first row is a broken log, and must
        # not be able to end the stream while looking like the end of the log.
        raise CtError(f"{log.name}: get-entries returned no usable entry at {start}")
    return out


def entries(log: Log, start: int, end: int | None = None, *,
            timeout: float = 30) -> Iterator[tuple[int, bytes]]:
    """Page a range, yielding (index, leaf_input) for parse_leaf.

    end defaults to the current tree head. Short reads, empty answers and rate
    limits are handled here so a caller never pages by hand. Nothing is
    requested until the first entry is asked for, but bad arguments are
    rejected at the call rather than at the first yield.
    """
    if start < 0:
        raise ValueError("start must not be negative")
    if end is not None and end < start - 1:
        raise ValueError("end must not precede start")
    return _page(log, start, end, timeout)


def _page(log: Log, start: int, end: int | None,
          timeout: float) -> Iterator[tuple[int, bytes]]:
    if end is None:
        end = tree_size(log, timeout=timeout) - 1

    position = start
    while position <= end:
        batch = fetch(log, position, min(end, position + MAX_BATCH - 1),
                      timeout=timeout)
        if not batch:
            # Nothing for a range the log accepted: the pass is over. Asking
            # again would spin forever against a log that has stalled.
            return
        for index, leaf_input, _extra in batch:
            yield index, leaf_input
        # By what arrived, never by what was asked for.
        position += len(batch)


def _usable(entry: object, operator: str, now: datetime,
            cafile: str | None) -> Log | None:
    if not isinstance(entry, dict):
        return None
    url = entry.get("url")
    if not isinstance(url, str) or not _is_https(url):
        return None
    # state is an object holding exactly one key, and that key is the state.
    state = entry.get("state")
    if not isinstance(state, dict) or len(state) != 1 or "usable" not in state:
        return None
    if not _covers(entry.get("temporal_interval"), now):
        return None
    name = entry.get("description")
    return Log(name=name if isinstance(name, str) else url, url=url,
               operator=operator, cafile=cafile)


def _covers(interval: object, now: datetime) -> bool:
    """Whether a temporal_interval includes now. A log without one is current."""
    if interval is None:
        return True
    if not isinstance(interval, dict):
        return False
    start = _timestamp(interval.get("start_inclusive"))
    end = _timestamp(interval.get("end_exclusive"))
    if start is not None and now < start:
        return False
    if end is not None and now >= end:
        return False
    return True


def _timestamp(text: object) -> datetime | None:
    if not isinstance(text, str) or len(text) > 64:
        return None
    try:
        # fromisoformat only learned to read a trailing Z in 3.11.
        when = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _entry(row: object) -> tuple[bytes, bytes] | None:
    if not isinstance(row, dict):
        return None
    leaf = _b64(row.get("leaf_input"))
    if leaf is None:
        return None
    extra = _b64(row.get("extra_data"))
    return None if extra is None else (leaf, extra)


def _b64(text: object) -> bytes | None:
    if not isinstance(text, str):
        return None
    # Bound the encoded form before decoding, so an oversized field costs a
    # length check rather than an allocation.
    if len(text) > MAX_ENTRY_BYTES // 3 * 4 + 4:
        return None
    try:
        # Strict about the alphabet, forgiving about a wrapped encoding.
        return base64.b64decode("".join(text.split()), validate=True)
    except ValueError:      # binascii.Error is one of these
        return None


def _items(value: object) -> tuple:
    return tuple(value) if isinstance(value, list) else ()


def _json(raw: bytes, what: str) -> object:
    try:
        return json.loads(raw)
    except RecursionError as err:
        # json recurses per nesting level, and a few kilobytes of brackets
        # unwinds the caller's stack. RecursionError is not a ValueError.
        raise CtError(f"{what} response is nested too deeply") from err
    except ValueError as err:
        raise CtError(f"{what} response is not JSON: {err}") from err


def _is_https(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.netloc)


def _endpoint(log: Log, path: str) -> str:
    # A log URL arrives over the network, and urlopen speaks file: and ftp: as
    # happily as it speaks https.
    if not _is_https(log.url):
        raise CtError(f"{log.name}: refusing a log URL that is not HTTPS")
    return f"{log.url.rstrip('/')}/ct/v1/{path}"


_CONTEXTS: dict[str | None, ssl.SSLContext] = {}


def _context(cafile: str | None) -> ssl.SSLContext:
    """Built once per trust configuration; loading a CA bundle is not cheap."""
    ctx = _CONTEXTS.get(cafile)
    if ctx is None:
        ctx = _CONTEXTS[cafile] = tls.context(cafile)
    return ctx


def _get(url: str, *, timeout: float, cafile: str | None, limit: int) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    context = _context(cafile)

    for attempt in range(MAX_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=timeout,
                                        context=context) as response:
                _same_origin(url, response)
                return _bounded(response, limit)
        except urllib.error.HTTPError as err:
            status = err.code
            delay = _retry_after(getattr(err, "headers", None))
            if getattr(err, "fp", None) is not None:
                err.close()
            if status not in RETRY_STATUS or attempt == MAX_ATTEMPTS - 1:
                raise HttpError(status, f"{url} returned HTTP {status}") from err
            if delay is None:
                delay = _backoff(attempt)
        except urllib.error.URLError as err:
            # A certificate that does not verify will not verify on the retry,
            # and this tool does not get to shrug at that.
            if isinstance(err.reason, ssl.SSLError):
                raise CtError(f"{url}: TLS verification failed: {err.reason}") from err
            if attempt == MAX_ATTEMPTS - 1:
                raise CtError(f"{url} unreachable: {err.reason}") from err
            delay = _backoff(attempt)
        except (http.client.HTTPException, OSError) as err:
            # A body that stops halfway, a status line that is not one, a TLS
            # record error after the handshake: http.client raises its own
            # exceptions and none of them are URLError. None may escape raw.
            if attempt == MAX_ATTEMPTS - 1:
                raise CtError(f"{url} unreachable: {err!r}") from err
            delay = _backoff(attempt)
        _sleep(delay)

    raise CtError(f"{url}: gave up after {MAX_ATTEMPTS} attempts")


def _same_origin(url: str, response) -> None:
    """Refuse a redirect that left HTTPS, or the host that was asked.

    urlopen follows 30x to http: and ftp: without a word, so a log answering
    with a redirect would otherwise be read in cleartext however carefully a
    verifying context was handed in.
    """
    final = getattr(response, "url", None)
    if not isinstance(final, str) or final == url:
        return
    try:
        want, got = urllib.parse.urlsplit(url), urllib.parse.urlsplit(final)
    except ValueError:
        raise CtError(f"{url}: redirected to an unreadable URL") from None
    if got.scheme != "https" or got.netloc != want.netloc:
        raise CtError(f"{url}: refusing a redirect to {final}")


def _bounded(response, limit: int) -> bytes:
    # One byte past the cap is enough to know the response is too large,
    # without reading the rest of it.
    body = response.read(limit + 1)
    if not isinstance(body, bytes):
        raise CtError("response body was not bytes")
    if len(body) > limit:
        raise CtError(f"response exceeds the {limit} byte cap")
    return body


def _backoff(attempt: int) -> float:
    """Exponential, with jitter so several logs do not retry in lockstep."""
    ceiling = min(BACKOFF_BASE * 2 ** attempt, MAX_BACKOFF)
    return ceiling * (0.5 + random.random() / 2)


def _retry_after(headers) -> float | None:
    """Seconds to wait per a Retry-After header, in either of its two forms."""
    if headers is None:
        return None
    raw = headers.get("Retry-After")
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    # isdigit() alone is true of superscripts and Arabic-Indic digits, which
    # float() either misreads or refuses outright.
    if raw.isascii() and raw.isdigit():
        return min(float(raw), MAX_RETRY_AFTER)
    try:
        when = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    seconds = (when - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, min(seconds, MAX_RETRY_AFTER))
