"""
Tests for the SMTP DATA-phase implementation:

  * the chunked body reader (`SMTPHoneypot._receive_mail_body`)
  * the filesystem storage helper (`mail_storage.store_mail_body`)
"""
import os
import socket
from pathlib import Path

import pytest

from mailoney.core import (
    MAX_MAIL_BODY_BYTES,
    SMTPHoneypot,
)
from mailoney import mail_storage


def _make_recv(*chunks: bytes):
    """Build a recv-shaped callable that yields the given chunks in order.

    Honours the buffer-size contract: if a scripted chunk is larger than
    the requested size, returns the head and queues the tail for the next
    call.
    """
    queue = list(chunks)

    def _recv(size: int) -> bytes:
        if not queue:
            return b""
        chunk = queue.pop(0)
        if len(chunk) <= size:
            return chunk
        queue.insert(0, chunk[size:])
        return chunk[:size]

    return _recv


def _make_recv_then_timeout(*chunks: bytes):
    """A recv-shaped callable that yields the given chunks, then raises
    ``socket.timeout`` — simulating a client that stalls mid-body once the
    socket has an inactivity timeout set.
    """
    queue = list(chunks)

    def _recv(size: int) -> bytes:
        if queue:
            return queue.pop(0)
        raise socket.timeout()

    return _recv


@pytest.fixture
def honeypot():
    return SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)


def test_receive_body_single_chunk(honeypot):
    body, found = honeypot._receive_mail_body(
        _make_recv(b"Subject: hi\r\n\r\nHello world\r\n.\r\n")
    )
    assert found is True
    assert body == b"Subject: hi\r\n\r\nHello world"


def test_receive_body_multiple_chunks(honeypot):
    """The reader must reassemble across recv() boundaries."""
    body, found = honeypot._receive_mail_body(
        _make_recv(
            b"Subject: split\r\n\r\nFirst half ",
            b"second half\r\n.\r\n",
        )
    )
    assert found is True
    assert body == b"Subject: split\r\n\r\nFirst half second half"


def test_receive_body_terminator_split_across_boundary(honeypot):
    """`\\r\\n.\\r\\n` arriving in two recv() calls is still detected."""
    body, found = honeypot._receive_mail_body(
        _make_recv(
            b"hello world\r\n",
            b".\r\n",
        )
    )
    assert found is True
    assert body == b"hello world"


def test_receive_body_permissive_terminator(honeypot):
    """`\\n.\\n` (LF-only) is also recognised."""
    body, found = honeypot._receive_mail_body(
        _make_recv(b"loose body\n.\n")
    )
    assert found is True
    assert body == b"loose body"


def test_receive_body_empty(honeypot):
    """A body that's just the terminator (empty message) returns empty bytes."""
    body, found = honeypot._receive_mail_body(_make_recv(b".\r\n"))
    assert found is True
    assert body == b""


def test_receive_body_peer_close_without_terminator(honeypot):
    """Peer disconnects mid-body — return what we have, found=False."""
    body, found = honeypot._receive_mail_body(_make_recv(b"truncated"))
    assert found is False
    assert body == b"truncated"


def test_receive_body_size_cap_truncates(honeypot):
    """At the cap, recv loop stops, found=False, body is exactly cap-sized."""
    payload = b"x" * 200_000  # > a recv buffer, < the cap
    body, found = honeypot._receive_mail_body(
        _make_recv(payload * 10),  # 2 MB total — exceeds 1 MB cap
        max_bytes=500_000,
    )
    assert found is False
    assert len(body) == 500_000


def test_receive_body_command_like_content_is_not_interpreted(honeypot):
    """Bytes inside the body that look like SMTP commands stay opaque."""
    body, found = honeypot._receive_mail_body(
        _make_recv(b"This body contains QUIT and EHLO foo\r\n.\r\n")
    )
    assert found is True
    assert b"QUIT" in body
    assert b"EHLO" in body


def test_receive_body_recv_timeout_truncates(honeypot):
    """A recv() timeout mid-body yields a truncated result, not a hang.

    Without this the handler thread blocks forever on a stalled client.
    """
    body, found = honeypot._receive_mail_body(
        _make_recv_then_timeout(b"partial body before the client stalled")
    )
    assert found is False
    assert body == b"partial body before the client stalled"


# --- mail_storage --------------------------------------------------------


def test_store_mail_body_writes_file_with_expected_layout(tmp_path):
    rel = mail_storage.store_mail_body(
        str(tmp_path), "192.0.2.1", "abc-123", b"hello body\r\n",
    )
    abs_path = tmp_path / rel
    assert abs_path.exists()
    assert abs_path.read_bytes() == b"hello body\r\n"
    # YYYY-MM-DD / src-ip / uuid.eml
    parts = Path(rel).parts
    assert len(parts) == 3
    assert parts[1] == "192.0.2.1"
    assert parts[2] == "abc-123.eml"


def test_store_mail_body_preserves_ipv6_colons(tmp_path):
    rel = mail_storage.store_mail_body(
        str(tmp_path), "2001:db8::1", "uuid-x", b"x",
    )
    parts = Path(rel).parts
    assert parts[1] == "2001:db8::1"
    assert (tmp_path / rel).exists()


def test_store_mail_body_strips_unsafe_characters(tmp_path):
    """Garbage in the IP gets dropped, but a path is still produced."""
    rel = mail_storage.store_mail_body(
        str(tmp_path), "../../../etc/passwd", "uuid-y", b"bytes",
    )
    parts = Path(rel).parts
    # No path traversal should survive.
    assert ".." not in parts
    assert "etc" not in parts
    assert (tmp_path / rel).exists()


def test_store_mail_body_sets_restrictive_mode(tmp_path):
    rel = mail_storage.store_mail_body(
        str(tmp_path), "10.0.0.1", "uuid-z", b"x",
    )
    abs_path = tmp_path / rel
    mode = os.stat(abs_path).st_mode & 0o777
    assert mode == 0o640
