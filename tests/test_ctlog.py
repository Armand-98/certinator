"""CT log client tests.

Every response is built here from the RFC 6962 and log list v3 formats rather
than captured from a server, so a pass means agreement with the specification.
Nothing touches the network: urlopen is replaced by a Server that answers from
these fixtures and records exactly what was asked of it.
"""

import base64
import datetime
import email.message
import http.client
import json
import ssl
import struct
import urllib.error
import urllib.parse

import pytest

from certinator import ctlog
from certinator.ctlog import CtError, HttpError, Log
from certinator.leaf import PRECERT_ENTRY, X509_ENTRY, parse_leaf

LOG = Log(name="test log", url="https://ct.example.com/log2026/")


# --------------------------------------------------------------------------
# fixtures: a fake HTTP server, built from the wire formats

class Response:
    """What urlopen returns: a context manager with a bounded read."""

    def __init__(self, body, status=200, url=None):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status = status
        self.url = url          # the final URL, after any redirect
        self.read_sizes = []
        self.closed = False

    def read(self, amt=None):
        self.read_sizes.append(amt)
        return self.body if amt is None else self.body[:amt]

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
        return False


def http_error(status, headers=None):
    message = email.message.Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return urllib.error.HTTPError("https://ct.example.com/", status, "rejected",
                                  message, None)


class Server:
    """Stands in for urlopen, recording every request it is handed."""

    def __init__(self, handler):
        self.handler = handler
        self.urls = []
        self.requests = []
        self.contexts = []
        self.timeouts = []
        self.responses = []

    def __call__(self, request, timeout=None, context=None):
        self.urls.append(request.full_url)
        self.requests.append(request)
        self.contexts.append(context)
        self.timeouts.append(timeout)
        answer = self.handler(request.full_url) if callable(self.handler) \
            else self.handler.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, Response) and answer.url is None:
            answer.url = request.full_url
        self.responses.append(answer)
        return answer

    @property
    def windows(self):
        out = []
        for url in self.urls:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            if "start" in query:
                out.append((int(query["start"][0]), int(query["end"][0])))
        return out


@pytest.fixture
def sleeps(monkeypatch):
    recorded = []
    monkeypatch.setattr(ctlog, "_sleep", recorded.append)
    return recorded


def serve(monkeypatch, handler):
    """Install a Server in place of urlopen. Anything else raises."""
    server = Server(handler)
    monkeypatch.setattr(ctlog.urllib.request, "urlopen", server)
    return server


def always(*answers):
    """Answer with each in turn, repeating the last one forever."""
    queue = list(answers)

    def handler(_url):
        return queue.pop(0) if len(queue) > 1 else queue[0]
    return handler


def leaf(timestamp=1_700_000_000_000, entry_type=X509_ENTRY, der=b"CERT"):
    """A MerkleTreeLeaf, per RFC 6962 section 3.4."""
    out = bytes([0, 0]) + struct.pack(">QH", timestamp, entry_type)
    if entry_type == PRECERT_ENTRY:
        out += b"\xaa" * 32
    out += len(der).to_bytes(3, "big") + der
    return out + struct.pack(">H", 0)


def entries_body(count, first=0, extra=b"chain"):
    return {"entries": [{"leaf_input": base64.b64encode(leaf(der=b"CERT%d" % n)).decode(),
                         "extra_data": base64.b64encode(extra).decode()}
                        for n in range(first, first + count)]}


def sth(size=100):
    return {"tree_size": size, "timestamp": 1_700_000_000_000,
            "sha256_root_hash": base64.b64encode(b"\x01" * 32).decode(),
            "tree_head_signature": ""}


def iso(days):
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def log_entry(url="https://ct.example.com/log2026/", description="Example 2026",
              state="usable", interval=(-30, 300)):
    entry = {"description": description, "log_id": "aaa=", "key": "bbb=",
             "url": url, "mmd": 86400}
    if state is not None:
        entry["state"] = {state: {"timestamp": iso(-400)}}
    if interval is not None:
        entry["temporal_interval"] = {"start_inclusive": iso(interval[0]),
                                      "end_exclusive": iso(interval[1])}
    return entry


def log_list(*logs, operator="Example Operator"):
    return {"version": "3.0", "operators": [{"name": operator, "email": [],
                                             "logs": list(logs)}]}


# --------------------------------------------------------------------------
# discover

def test_discover_returns_usable_logs_covering_now(monkeypatch):
    serve(monkeypatch, always(Response(log_list(log_entry()))))
    logs = ctlog.discover()
    assert [(log.name, log.url, log.operator) for log in logs] == [
        ("Example 2026", "https://ct.example.com/log2026/", "Example Operator")]


def test_discover_fetches_the_published_log_list(monkeypatch):
    server = serve(monkeypatch, always(Response(log_list(log_entry()))))
    ctlog.discover()
    assert server.urls == [ctlog.LOG_LIST_URL]


@pytest.mark.parametrize("state", ["pending", "qualified", "readonly",
                                   "retired", "rejected"])
def test_discover_keeps_only_usable_logs(monkeypatch, state):
    """A log's state object holds exactly one key, and that key is the state."""
    serve(monkeypatch, always(Response(log_list(log_entry(state=state)))))
    assert ctlog.discover() == []


def test_discover_drops_a_log_whose_shard_has_expired(monkeypatch):
    serve(monkeypatch, always(Response(log_list(log_entry(interval=(-400, -1))))))
    assert ctlog.discover() == []


def test_discover_drops_a_log_whose_shard_has_not_opened(monkeypatch):
    """Half the usable logs at any moment are next year's shards."""
    serve(monkeypatch, always(Response(log_list(log_entry(interval=(30, 400))))))
    assert ctlog.discover() == []


def test_discover_keeps_a_log_with_no_temporal_interval(monkeypatch):
    serve(monkeypatch, always(Response(log_list(log_entry(interval=None)))))
    assert len(ctlog.discover()) == 1


def test_discover_reads_intervals_without_a_zulu_suffix(monkeypatch):
    entry = log_entry()
    entry["temporal_interval"] = {"start_inclusive": "2020-01-01T00:00:00+00:00",
                                  "end_exclusive": "2099-01-01T00:00:00+00:00"}
    serve(monkeypatch, always(Response(log_list(entry))))
    assert len(ctlog.discover()) == 1


def test_discover_spans_every_operator(monkeypatch):
    body = log_list(log_entry(url="https://a.example.com/"), operator="A")
    body["operators"].append({"name": "B", "logs": [log_entry(url="https://b.example.com/")]})
    serve(monkeypatch, always(Response(body)))
    assert [log.operator for log in ctlog.discover()] == ["A", "B"]


@pytest.mark.parametrize("entry", [
    {"url": "https://ct.example.com/", "state": {"usable": {}}},          # no interval key is fine
    {"url": "http://ct.example.com/", "state": {"usable": {}}},           # not HTTPS
    {"url": "file:///etc/passwd", "state": {"usable": {}}},
    {"url": "https://ct.example.com/"},                                   # no state
    {"state": {"usable": {}}},                                            # no url
    {"url": 7, "state": {"usable": {}}},
    {"url": "https://ct.example.com/", "state": "usable"},
    {"url": "https://ct.example.com/", "state": {}},
    {"url": "https://ct.example.com/", "state": {"usable": {}, "retired": {}}},
    {"url": "https://ct.example.com/", "state": {"usable": {}},
     "temporal_interval": "always"},
    {"url": "https://ct.example.com/", "state": {"usable": {}},
     "temporal_interval": {"start_inclusive": "not a date", "end_exclusive": 5}},
    "a log that is a string",
    None,
])
def test_discover_survives_hostile_log_list_entries(monkeypatch, entry):
    """One unusable entry must never cost the other logs, or raise."""
    serve(monkeypatch, always(Response(log_list(entry, log_entry()))))
    good = [log for log in ctlog.discover() if log.name == "Example 2026"]
    assert len(good) == 1


@pytest.mark.parametrize("body", [b"", b"not json", b"{", b'{"operators":',
                                  b'\xff\xfe\x00'])
def test_discover_rejects_a_log_list_that_is_not_json(monkeypatch, body):
    serve(monkeypatch, always(Response(body)))
    with pytest.raises(CtError, match="not JSON"):
        ctlog.discover()


@pytest.mark.parametrize("body", [b"[1, 2, 3]", b"null", b'"log list"'])
def test_discover_rejects_a_log_list_that_is_not_an_object(monkeypatch, body):
    serve(monkeypatch, always(Response(body)))
    with pytest.raises(CtError, match="not a JSON object"):
        ctlog.discover()


@pytest.mark.parametrize("body", [{}, {"operators": "many"}, {"operators": {}},
                                  {"operators": [None, 7, "x"]},
                                  {"operators": [{"logs": "none"}]}])
def test_discover_reports_no_logs_rather_than_raising(monkeypatch, body):
    serve(monkeypatch, always(Response(body)))
    assert ctlog.discover() == []


def test_discover_refuses_an_oversized_log_list(monkeypatch):
    monkeypatch.setattr(ctlog, "MAX_LOG_LIST_BYTES", 64)
    server = serve(monkeypatch, always(Response(b"{" + b"x" * 4096)))
    with pytest.raises(CtError, match="byte cap"):
        ctlog.discover()
    # Bounded at the read, not after the whole body was in memory.
    assert server.responses[0].read_sizes == [65]


# --------------------------------------------------------------------------
# get-sth

def test_tree_size(monkeypatch):
    server = serve(monkeypatch, always(Response(sth(3_141_592))))
    assert ctlog.tree_size(LOG) == 3_141_592
    assert server.urls == ["https://ct.example.com/log2026/ct/v1/get-sth"]


def test_endpoints_survive_a_log_url_without_a_trailing_slash(monkeypatch):
    server = serve(monkeypatch, always(Response(sth())))
    ctlog.tree_size(Log(name="n", url="https://ct.example.com/log2026"))
    assert server.urls == ["https://ct.example.com/log2026/ct/v1/get-sth"]


@pytest.mark.parametrize("body", [{}, {"tree_size": -1}, {"tree_size": "10"},
                                  {"tree_size": 1.5}, {"tree_size": True},
                                  {"tree_size": None}, [1], "sth"])
def test_tree_size_rejects_anything_that_is_not_a_count(monkeypatch, body):
    serve(monkeypatch, always(Response(body)))
    with pytest.raises(CtError):
        ctlog.tree_size(LOG)


def test_a_log_url_that_is_not_https_is_never_requested(monkeypatch):
    """urlopen speaks file: and ftp:, and log URLs arrive over the network."""
    server = serve(monkeypatch, always(Response(sth())))
    with pytest.raises(CtError, match="HTTPS"):
        ctlog.tree_size(Log(name="bad", url="http://ct.example.com/"))
    assert server.urls == []


# --------------------------------------------------------------------------
# get-entries

def test_fetch_decodes_base64_and_numbers_the_entries(monkeypatch):
    server = serve(monkeypatch, always(Response(entries_body(3))))
    got = ctlog.fetch(LOG, 10, 12)
    assert [index for index, _, _ in got] == [10, 11, 12]
    assert got[0][1] == leaf(der=b"CERT0")
    assert got[0][2] == b"chain"
    assert server.windows == [(10, 12)]


def test_leaf_input_feeds_parse_leaf(monkeypatch):
    body = {"entries": [{"leaf_input": base64.b64encode(
        leaf(entry_type=PRECERT_ENTRY, der=b"TBS")).decode(), "extra_data": ""}]}
    serve(monkeypatch, always(Response(body)))
    _, leaf_input, _ = ctlog.fetch(LOG, 0, 0)[0]
    parsed = parse_leaf(leaf_input)
    assert parsed.is_precert and parsed.der == b"TBS"


def test_a_short_read_is_reported_as_what_arrived(monkeypatch):
    """Asking for 1000 and being given 32 is normal, not an error."""
    serve(monkeypatch, always(Response(entries_body(32))))
    got = ctlog.fetch(LOG, 0, 999)
    assert len(got) == 32
    assert [index for index, _, _ in got] == list(range(32))


def test_fetch_drops_entries_past_the_window_it_asked_for(monkeypatch):
    serve(monkeypatch, always(Response(entries_body(50))))
    assert len(ctlog.fetch(LOG, 0, 9)) == 10


def test_fetch_clamps_an_absurd_window(monkeypatch):
    server = serve(monkeypatch, always(Response(entries_body(1))))
    ctlog.fetch(LOG, 0, 10_000_000)
    assert server.windows == [(0, ctlog.MAX_BATCH - 1)]


def test_fetch_returns_nothing_for_a_start_past_the_tree(monkeypatch):
    """400 is how a log says "that index does not exist yet"."""
    server = serve(monkeypatch, always(http_error(400)))
    assert ctlog.fetch(LOG, 10 ** 9, 10 ** 9) == []
    assert len(server.urls) == 1        # not retried


def test_fetch_raises_on_a_status_it_cannot_interpret(monkeypatch):
    serve(monkeypatch, always(http_error(404)))
    with pytest.raises(HttpError) as caught:
        ctlog.fetch(LOG, 0, 9)
    assert caught.value.status == 404


@pytest.mark.parametrize("body", [b"{", b"{}", b'{"entries": "none"}',
                                  b'{"entries": {}}', b"[]"])
def test_fetch_rejects_a_response_that_is_not_a_get_entries_body(monkeypatch, body):
    serve(monkeypatch, always(Response(body)))
    with pytest.raises(CtError):
        ctlog.fetch(LOG, 0, 9)


def test_fetch_returns_an_empty_batch_for_an_empty_entries_array(monkeypatch):
    serve(monkeypatch, always(Response({"entries": []})))
    assert ctlog.fetch(LOG, 0, 9) == []


@pytest.mark.parametrize("row", [
    {"leaf_input": "!!!not base64!!!", "extra_data": ""},
    {"leaf_input": "AAAA", "extra_data": "!!!"},
    {"extra_data": "AAAA"},
    {"leaf_input": 5, "extra_data": ""},
    {"leaf_input": None, "extra_data": None},
    "an entry that is a string",
    None,
])
def test_a_malformed_entry_truncates_the_batch_rather_than_shifting_indices(
        monkeypatch, row):
    """Skipping a bad row would make every later index name the wrong entry."""
    body = entries_body(3)
    body["entries"].insert(1, row)
    serve(monkeypatch, always(Response(body)))
    got = ctlog.fetch(LOG, 100, 103)
    assert [index for index, _, _ in got] == [100]


def test_a_wrapped_encoding_still_decodes(monkeypatch):
    body = b"WRAPPED" * 32
    raw = base64.encodebytes(leaf(der=body)).decode()        # newline every 76
    assert "\n" in raw.strip()
    serve(monkeypatch, always(Response({"entries": [{"leaf_input": raw,
                                                     "extra_data": ""}]})))
    assert parse_leaf(ctlog.fetch(LOG, 0, 0)[0][1]).der == body


def test_an_oversized_entry_field_is_refused_before_it_is_decoded(monkeypatch):
    monkeypatch.setattr(ctlog, "MAX_ENTRY_BYTES", 16)
    body = {"entries": [{"leaf_input": base64.b64encode(b"ok").decode(),
                         "extra_data": ""},
                        {"leaf_input": base64.b64encode(b"x" * 4096).decode(),
                         "extra_data": ""}]}
    serve(monkeypatch, always(Response(body)))
    assert [index for index, _, _ in ctlog.fetch(LOG, 0, 1)] == [0]


def test_a_gigantic_response_is_refused_rather_than_read(monkeypatch):
    monkeypatch.setattr(ctlog, "MAX_ENTRIES_BYTES", 128)
    server = serve(monkeypatch, always(Response(b"x" * (1 << 20))))
    with pytest.raises(CtError, match="byte cap"):
        ctlog.fetch(LOG, 0, 9)
    assert server.responses[0].read_sizes == [129]


@pytest.mark.parametrize("start,end", [(-1, 5), (5, 4), (-5, -6)])
def test_fetch_rejects_impossible_windows(start, end):
    with pytest.raises(ValueError):
        ctlog.fetch(LOG, start, end)


# --------------------------------------------------------------------------
# rate limiting

def test_rate_limiting_is_retried_and_the_wait_is_honoured(monkeypatch, sleeps):
    server = serve(monkeypatch, always(http_error(429, {"Retry-After": "7"}),
                                       Response(entries_body(1))))
    assert len(ctlog.fetch(LOG, 0, 0)) == 1
    assert len(server.urls) == 2
    assert sleeps == [7.0]


def test_service_unavailable_is_retried(monkeypatch, sleeps):
    serve(monkeypatch, always(http_error(503), Response(entries_body(2))))
    assert len(ctlog.fetch(LOG, 0, 1)) == 2
    assert len(sleeps) == 1


def test_a_retry_after_date_is_honoured(monkeypatch, sleeps):
    when = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=30)
    header = when.strftime("%a, %d %b %Y %H:%M:%S GMT")
    serve(monkeypatch, always(http_error(429, {"Retry-After": header}),
                              Response(sth(4))))
    assert ctlog.tree_size(LOG) == 4
    assert 25 <= sleeps[0] <= 31


def test_a_retry_after_date_in_the_past_does_not_sleep_backwards(monkeypatch, sleeps):
    serve(monkeypatch, always(http_error(429, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}),
                              Response(sth(1))))
    ctlog.tree_size(LOG)
    assert sleeps == [0.0]


def test_an_absurd_retry_after_is_capped(monkeypatch, sleeps):
    serve(monkeypatch, always(http_error(429, {"Retry-After": "999999"}),
                              Response(sth(1))))
    ctlog.tree_size(LOG)
    assert sleeps == [ctlog.MAX_RETRY_AFTER]


def test_a_nonsense_retry_after_falls_back_to_backoff(monkeypatch, sleeps):
    serve(monkeypatch, always(http_error(429, {"Retry-After": "soon"}),
                              Response(sth(1))))
    ctlog.tree_size(LOG)
    assert 0 < sleeps[0] <= ctlog.BACKOFF_BASE


def test_retrying_gives_up_instead_of_hammering(monkeypatch, sleeps):
    server = serve(monkeypatch, always(http_error(429)))
    with pytest.raises(HttpError) as caught:
        ctlog.fetch(LOG, 0, 9)
    assert caught.value.status == 429
    assert len(server.urls) == ctlog.MAX_ATTEMPTS
    assert len(sleeps) == ctlog.MAX_ATTEMPTS - 1
    assert sleeps[-1] > sleeps[0]                       # exponential
    assert all(delay <= ctlog.MAX_BACKOFF for delay in sleeps)


def test_a_network_failure_is_retried_then_reported(monkeypatch, sleeps):
    server = serve(monkeypatch, always(urllib.error.URLError("connection refused")))
    with pytest.raises(CtError, match="unreachable"):
        ctlog.tree_size(LOG)
    assert len(server.urls) == ctlog.MAX_ATTEMPTS


def test_a_certificate_that_does_not_verify_is_never_retried(monkeypatch, sleeps):
    """Retrying a trust failure only makes the same wrong answer more slowly."""
    failure = urllib.error.URLError(
        ssl.SSLCertVerificationError("unable to get local issuer certificate"))
    server = serve(monkeypatch, always(failure))
    with pytest.raises(CtError, match="TLS verification failed"):
        ctlog.tree_size(LOG)
    assert len(server.urls) == 1
    assert sleeps == []


def test_a_timeout_is_retried(monkeypatch, sleeps):
    server = serve(monkeypatch, always(TimeoutError("timed out"), Response(sth(2))))
    assert ctlog.tree_size(LOG) == 2
    assert len(server.urls) == 2


# --------------------------------------------------------------------------
# paging

def short_reads(per_call=32, size=100):
    """A log that answers with at most per_call entries, however many are asked."""
    def handler(url):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        if "start" not in query:
            return Response(sth(size))
        start, end = int(query["start"][0]), int(query["end"][0])
        if start >= size:
            return http_error(400)
        count = min(per_call, end - start + 1, size - start)
        return Response(entries_body(count))
    return handler


def test_paging_advances_by_what_arrived_not_by_what_was_asked_for(monkeypatch):
    """The single most common bug in CT clients: a cursor moved by the request
    window skips every entry a short read did not return."""
    server = serve(monkeypatch, short_reads(per_call=32, size=100))
    got = list(ctlog.entries(LOG, 0, 99))
    assert [index for index, _ in got] == list(range(100))
    assert server.windows == [(0, 99), (32, 99), (64, 99), (96, 99)]


def test_paging_yields_leaf_inputs_that_parse(monkeypatch):
    serve(monkeypatch, short_reads(per_call=4, size=8))
    assert all(parse_leaf(raw).timestamp == 1_700_000_000_000
               for _, raw in ctlog.entries(LOG, 0, 7))


def test_paging_stops_when_a_log_returns_nothing(monkeypatch):
    """A valid range answered with zero entries ends the pass. Asking again
    would loop forever against a log that has stalled."""
    server = serve(monkeypatch, always(Response(entries_body(32)),
                                       Response({"entries": []})))
    got = list(ctlog.entries(LOG, 0, 10_000))
    assert len(got) == 32
    assert len(server.urls) == 2


def test_paging_stops_at_the_end_of_the_tree(monkeypatch):
    serve(monkeypatch, short_reads(per_call=32, size=100))
    got = list(ctlog.entries(LOG, 90, 10_000))
    assert [index for index, _ in got] == list(range(90, 100))


def test_paging_defaults_to_the_current_tree_head(monkeypatch):
    server = serve(monkeypatch, short_reads(per_call=32, size=40))
    got = list(ctlog.entries(LOG, 0))
    assert [index for index, _ in got] == list(range(40))
    assert server.urls[0].endswith("/ct/v1/get-sth")
    assert server.windows[0] == (0, 39)


def test_paging_an_empty_log_asks_for_nothing(monkeypatch):
    server = serve(monkeypatch, always(Response(sth(0))))
    assert list(ctlog.entries(LOG, 0)) == []
    assert server.windows == []


def test_paging_never_asks_for_more_than_one_batch_at_a_time(monkeypatch):
    server = serve(monkeypatch, short_reads(per_call=ctlog.MAX_BATCH, size=2500))
    list(ctlog.entries(LOG, 0, 2499))
    assert server.windows == [(0, 999), (1000, 1999), (2000, 2499)]


def test_paging_is_lazy(monkeypatch):
    """A caller that stops early must not have paid for the whole range."""
    server = serve(monkeypatch, short_reads(per_call=32, size=1_000_000))
    stream = ctlog.entries(LOG, 0, 999_999)
    assert next(stream)[0] == 0
    assert len(server.urls) == 1


@pytest.mark.parametrize("start,end", [(-1, 10), (10, 8)])
def test_paging_rejects_impossible_ranges_at_the_call(start, end):
    """Not at the first yield, where a caller has stopped looking."""
    with pytest.raises(ValueError):
        ctlog.entries(LOG, start, end)


# --------------------------------------------------------------------------
# request shaping

def test_every_request_identifies_the_tool(monkeypatch):
    """Operators ask for a User-Agent so they can find whoever misbehaves."""
    server = serve(monkeypatch, short_reads(per_call=4, size=4))
    list(ctlog.entries(LOG, 0))
    assert len(server.requests) == 2
    for request in server.requests:
        assert request.get_header("User-agent") == ctlog.USER_AGENT
        assert "certinator" in ctlog.USER_AGENT


def test_every_request_verifies_the_certificate(monkeypatch):
    """A tool whose subject is certificates does not skip verification."""
    server = serve(monkeypatch, short_reads(per_call=4, size=4))
    list(ctlog.entries(LOG, 0))
    for context in server.contexts:
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
    assert len({id(context) for context in server.contexts}) == 1   # built once


def test_the_timeout_reaches_the_socket(monkeypatch):
    server = serve(monkeypatch, short_reads(per_call=4, size=4))
    list(ctlog.entries(LOG, 0, 3, timeout=2.5))
    assert server.timeouts == [2.5]


def test_the_ca_bundle_travels_with_the_log(monkeypatch):
    """tree_size and fetch take only a Log, so trust must live on the Log."""
    asked = []
    monkeypatch.setattr(ctlog, "_CONTEXTS", {})
    monkeypatch.setattr(ctlog.tls, "context", lambda cafile:
                        asked.append(cafile) or ssl.create_default_context())
    serve(monkeypatch, always(Response(log_list(log_entry())), Response(sth(9))))
    log = ctlog.discover(cafile="/etc/pki/bundle.pem")[0]
    assert log.cafile == "/etc/pki/bundle.pem"
    assert ctlog.tree_size(log) == 9
    assert asked == ["/etc/pki/bundle.pem"]


# --------------------------------------------------------------------------
# adversarial review: a log is a stranger, and none of this may escape as
# something other than CtError, nor stop the stream without saying so.

class Exploding(Response):
    """A response whose body read fails partway, as a cut connection does."""

    def __init__(self, error):
        super().__init__(b"", url="https://ct.example.com/log2026/ct/v1/get-entries")
        self.error = error

    def read(self, amt=None):
        raise self.error


def json_bomb(depth=20_000):
    return b"[" * depth + b"]" * depth


@pytest.mark.parametrize("call", [
    lambda: ctlog.discover(),
    lambda: ctlog.tree_size(LOG),
    lambda: ctlog.fetch(LOG, 0, 9),
])
def test_a_deeply_nested_body_is_refused_rather_than_recursing(monkeypatch, call):
    """json.loads recurses, and RecursionError is not a ValueError. 400KB of
    brackets sits well under every byte cap and unwinds the caller's stack."""
    serve(monkeypatch, always(Response(json_bomb())))
    with pytest.raises(CtError):
        call()


@pytest.mark.parametrize("header", ["²", "⁵", "٣٣٣٣٣٣٣٣"])
def test_an_exotic_digit_retry_after_falls_back_to_backoff(monkeypatch, sleeps,
                                                           header):
    """str.isdigit() is true for superscripts and fractions that float() will
    not read. A header is attacker chosen; it does not get to raise."""
    serve(monkeypatch, always(http_error(503, {"Retry-After": header}),
                              Response(sth(3))))
    assert ctlog.tree_size(LOG) == 3
    assert 0 < sleeps[0] <= ctlog.BACKOFF_BASE


@pytest.mark.parametrize("failure", [
    http.client.IncompleteRead(b"half"),
    http.client.BadStatusLine("garbage"),
    http.client.LineTooLong("header line"),
])
def test_a_broken_http_response_is_a_ct_error(monkeypatch, sleeps, failure):
    """http.client raises its own exceptions, and none of them are URLError."""
    server = serve(monkeypatch, always(failure))
    with pytest.raises(CtError):
        ctlog.tree_size(LOG)
    assert len(server.urls) == ctlog.MAX_ATTEMPTS


def test_a_connection_cut_during_the_body_is_a_ct_error(monkeypatch, sleeps):
    """A TLS record error after the handshake is not wrapped in URLError."""
    serve(monkeypatch, always(Exploding(ssl.SSLError("record layer failure"))))
    with pytest.raises(CtError):
        ctlog.fetch(LOG, 0, 9)


def test_backoff_actually_doubles(monkeypatch, sleeps):
    """Jitter is half to full, so each wait still clears half the last ceiling."""
    serve(monkeypatch, always(http_error(429)))
    with pytest.raises(HttpError):
        ctlog.tree_size(LOG)
    assert len(sleeps) == ctlog.MAX_ATTEMPTS - 1
    for attempt, delay in enumerate(sleeps):
        ceiling = min(ctlog.BACKOFF_BASE * 2 ** attempt, ctlog.MAX_BACKOFF)
        assert ceiling / 2 <= delay <= ceiling


@pytest.mark.parametrize("location", ["http://ct.example.com/log2026/",
                                      "ftp://ct.example.com/log2026/",
                                      "https://evil.example.net/log2026/"])
def test_a_redirect_off_https_is_refused(monkeypatch, location):
    """urlopen follows 30x to http: and ftp: without a word, which would read
    a log over cleartext after tls.context() was carefully handed in."""
    serve(monkeypatch, always(Response(sth(5), url=location + "ct/v1/get-sth")))
    with pytest.raises(CtError, match="redirect"):
        ctlog.tree_size(LOG)


def test_a_first_entry_that_is_malformed_is_not_the_end_of_the_log(monkeypatch):
    """Truncating at offset zero leaves an empty batch, which paging reads as
    end of stream: the watcher stops, silently, and reports nothing wrong."""
    body = entries_body(4)
    body["entries"][0] = {"leaf_input": "not base64!!", "extra_data": ""}
    server = serve(monkeypatch, always(Response(body)))
    with pytest.raises(CtError):
        list(ctlog.entries(LOG, 0, 3))
    assert len(server.urls) == 1


def test_a_batch_truncated_partway_stops_the_pass_loudly(monkeypatch):
    """The re-request lands on the bad row, and that must not read as caught up."""
    def handler(url):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        start = int(query["start"][0])
        body = entries_body(4 - start, first=start)
        body["entries"][2 - start if start == 0 else 0] = {"leaf_input": "@@@@",
                                                           "extra_data": ""}
        return Response(body)

    serve(monkeypatch, handler)
    stream = ctlog.entries(LOG, 0, 3)
    assert [next(stream)[0], next(stream)[0]] == [0, 1]
    with pytest.raises(CtError):
        next(stream)
