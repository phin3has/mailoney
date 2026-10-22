"""
Tests for the core module
"""
import pytest
import socket
import threading
from unittest.mock import patch, MagicMock
from mailoney.core import SMTPHoneypot, DEFAULT_CONN_TIMEOUT

@pytest.fixture
def smtp_honeypot():
    """Test SMTP honeypot fixture"""
    honeypot = SMTPHoneypot(
        bind_ip="127.0.0.1",
        bind_port=8025,
        server_name="test.example.com"
    )
    return honeypot

def test_smtp_honeypot_init(smtp_honeypot):
    """Test SMTP honeypot initialization"""
    assert smtp_honeypot.bind_ip == "127.0.0.1"
    assert smtp_honeypot.bind_port == 8025
    assert smtp_honeypot.server_name == "test.example.com"
    assert "test.example.com" in smtp_honeypot.ehlo_response
    assert smtp_honeypot.socket is None

@patch("socket.socket")
def test_smtp_honeypot_start(mock_socket, smtp_honeypot):
    """Test SMTP honeypot start method"""
    # Setup mock socket
    mock_socket_instance = MagicMock()
    mock_socket.return_value = mock_socket_instance
    
    # Create a simple counter to check if the method was called
    call_count = [0]
    
    # Define a replacement function that increments the counter
    def accept_connections_mock():
        call_count[0] += 1
        return None
    
    # Replace the method with our mock that increments the counter
    original_method = smtp_honeypot._accept_connections
    smtp_honeypot._accept_connections = accept_connections_mock
    
    try:
        # Call the start method
        smtp_honeypot.start()
        
        # Verify socket configuration
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket_instance.setsockopt.assert_called_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        mock_socket_instance.bind.assert_called_with(("127.0.0.1", 8025))
        mock_socket_instance.listen.assert_called_with(10)
        
        # Verify our function was called
        assert call_count[0] > 0, "The _accept_connections method was not called"
    finally:
        # Restore the original method
        smtp_honeypot._accept_connections = original_method


def test_conn_timeout_defaults(smtp_honeypot):
    """conn_timeout defaults to DEFAULT_CONN_TIMEOUT and is overridable."""
    assert smtp_honeypot.conn_timeout == DEFAULT_CONN_TIMEOUT
    assert SMTPHoneypot(conn_timeout=5).conn_timeout == 5


def test_idle_connection_times_out():
    """A client that connects and then sends nothing must be dropped after
    conn_timeout, freeing the handler thread (slow-loris protection).

    Without the timeout, _handle_client blocks forever on recv() and the
    thread never exits.
    """
    server_sock, client_sock = socket.socketpair()
    honeypot = SMTPHoneypot(
        bind_ip="127.0.0.1", bind_port=8025, conn_timeout=1
    )

    handler = threading.Thread(
        target=honeypot._handle_client,
        args=(server_sock, ("203.0.113.7", 54321)),
    )
    handler.start()

    # Client reads the banner, then deliberately sends nothing at all.
    banner = client_sock.recv(1024)
    assert banner.startswith(b"220 ")

    # The handler must exit on its own well within the join window.
    handler.join(timeout=5)
    assert not handler.is_alive(), "handler thread did not exit after timeout"

    # It should have sent a 421 timeout reply before closing the socket.
    client_sock.settimeout(2)
    tail = b""
    try:
        while True:
            chunk = client_sock.recv(1024)
            if not chunk:
                break
            tail += chunk
    except socket.timeout:
        pass
    assert b"421" in tail
    client_sock.close()


# --- session summary vs. transcript -----------------------------------
#
# Every session produces two records: the per-command transcript that goes
# to the database (unchanged shape), and a flat summary emitted as the
# session_ended event. These tests drive the handler with a mock socket
# and check both.

import json
from mailoney import metrics


def _mock_socket(*chunks):
    sock = MagicMock(spec=socket.socket)
    sock.recv.side_effect = list(chunks) + [b""]
    sock.send.side_effect = lambda b: len(b)
    return sock


def _session_ended(read_events):
    ended = [e for e in read_events() if e["event"] == "session_ended"]
    assert len(ended) == 1
    return ended[0]


def test_full_session_summary_and_transcript(event_stream):
    stored = {}
    sock = _mock_socket(
        b"EHLO probe\r\n",
        b"AUTH PLAIN dGVzdA==\r\n",
        b"MAIL FROM:<a@b.test>\r\n",
        b"RCPT TO:<c@d.test>\r\n",
        b"DATA\r\n",
        b"Subject: hi\r\n\r\nhello\r\n.\r\n",
        b"QUIT\r\n",
    )
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    with patch("mailoney.core.update_session_data",
               side_effect=lambda sid, data: stored.update(id=sid, data=data)):
        h._handle_client(sock, ("10.0.0.1", 4444))

    s = _session_ended(event_stream)
    assert s["src_ip"] == "10.0.0.1" and s["src_port"] == 4444
    assert s["dest_ip"] == "127.0.0.1" and s["dest_port"] == 8025
    assert s["outcome"] == "ok"
    assert s["last_response_code"] == 221
    assert s["command_count"] == 6
    assert s["commands"][0] == "ehlo probe" and s["commands"][-1] == "quit"
    assert s["credentials"] == ["dGVzdA=="]  # original case is preserved
    # "Subject: hi\r\n\r\nhello" = 20 bytes; the terminator is excluded.
    assert s["mail"] == [{"size": 20, "truncated": False}]
    assert s["mail_size"] == 20
    assert "commands_truncated" not in s and "timed_out" not in s
    assert "tls_version" not in s

    # The database still receives the transcript, not the summary.
    transcript = json.loads(stored["data"])
    assert isinstance(transcript, list)
    directions = [e["direction"] for e in transcript]
    assert directions[0] == "out"                       # banner
    assert directions.count("in") == 6
    assert "mail-body" in directions
    body_entry = next(e for e in transcript if e["direction"] == "mail-body")
    assert body_entry["size"] == 20 and body_entry["truncated"] is False
    assert all("timestamp" in e for e in transcript)


def test_commands_list_is_capped(event_stream):
    from mailoney.core import MAX_LOGGED_COMMANDS
    n = MAX_LOGGED_COMMANDS + 5
    sock = _mock_socket(*([b"EHLO x\r\n"] * n))
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    with patch("mailoney.core.update_session_data"):
        h._handle_client(sock, ("10.0.0.1", 4444))
    s = _session_ended(event_stream)
    assert s["command_count"] == n
    assert len(s["commands"]) == MAX_LOGGED_COMMANDS
    assert s["commands_truncated"] is True


def test_banner_only_session(event_stream):
    before = metrics.BANNER_ONLY_SESSIONS_TOTAL._value.get()
    sock = _mock_socket()  # client reads the banner and disconnects
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    with patch("mailoney.core.update_session_data"):
        h._handle_client(sock, ("10.0.0.1", 4444))
    s = _session_ended(event_stream)
    assert s["command_count"] == 0 and s["commands"] == []
    assert s["last_response_code"] == 220
    assert metrics.BANNER_ONLY_SESSIONS_TOTAL._value.get() == before + 1


def test_session_events_share_uuid(event_stream):
    sock = _mock_socket(b"AUTH PLAIN dGVzdA==\r\n", b"QUIT\r\n")
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    with patch("mailoney.core.update_session_data"):
        h._handle_client(sock, ("10.0.0.1", 4444))
    evs = event_stream()
    assert [e["event"] for e in evs] == ["session_started", "credential_captured", "session_ended"]
    assert len({e["session_uuid"] for e in evs}) == 1


# --- authentication handling ------------------------------------------

def _run(*chunks):
    sock = _mock_socket(*chunks)
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    with patch("mailoney.core.update_session_data"):
        h._handle_client(sock, ("10.0.0.1", 4444))
    return [c.args[0].decode() for c in sock.send.call_args_list]


def test_auth_plain_preserves_case(event_stream):
    # base64 is case-sensitive: "\0testuser\0Passw0rd!"
    blob = "AHRlc3R1c2VyAFBhc3N3MHJkIQ=="
    _run(b"EHLO x\r\n", f"AUTH PLAIN {blob}\r\n".encode(), b"QUIT\r\n")
    assert _session_ended(event_stream)["credentials"] == [blob]


def test_failed_auth_uses_535_not_235(event_stream):
    replies = _run(b"AUTH PLAIN dGVzdA==\r\n", b"QUIT\r\n")
    assert any(r.startswith("535 ") for r in replies)
    assert not any(r.startswith("235 ") for r in replies)


def test_auth_login_two_step_exchange(event_stream):
    # username "testuser", password "Passw0rd!"
    replies = _run(b"EHLO x\r\n", b"AUTH LOGIN\r\n", b"dGVzdHVzZXI=\r\n",
                   b"UGFzc3cwcmQh\r\n", b"QUIT\r\n")
    assert "334 VXNlcm5hbWU6\n" in replies      # "Username:"
    assert "334 UGFzc3dvcmQ6\n" in replies      # "Password:"
    assert any(r.startswith("535 ") for r in replies)
    assert not any(r.startswith("502 ") for r in replies)
    # Stored in the same shape as AUTH PLAIN, original case intact.
    assert _session_ended(event_stream)["credentials"] == ["AHRlc3R1c2VyAFBhc3N3MHJkIQ=="]


def test_auth_login_username_on_same_line(event_stream):
    replies = _run(b"AUTH LOGIN dGVzdHVzZXI=\r\n", b"UGFzc3cwcmQh\r\n", b"QUIT\r\n")
    assert "334 UGFzc3dvcmQ6\n" in replies
    assert _session_ended(event_stream)["credentials"] == ["AHRlc3R1c2VyAFBhc3N3MHJkIQ=="]


def test_auth_login_answers_are_not_treated_as_commands(event_stream):
    # A password that happens to look like a command must not be run as one.
    replies = _run(b"AUTH LOGIN\r\n", b"dXNlcg==\r\n", b"quit\r\n", b"QUIT\r\n")
    assert sum(r.startswith("221 ") for r in replies) == 1   # only the real QUIT
    assert _session_ended(event_stream)["command_count"] == 4
