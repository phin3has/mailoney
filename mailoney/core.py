"""
Core functionality for the Mailoney SMTP Honeypot
"""
import base64
import binascii
import os
import re
import socket
import ssl
import threading
import logging
import json
import sys
import uuid
import time
import argparse
from time import strftime
from typing import Optional, Tuple, Dict, Any, List

from .db import create_session, update_session_data, log_credential, init_db
from .config import get_settings, configure_logging
from .mail_storage import store_mail_body
from . import metrics
from . import events

class TLSConfigError(Exception):
    """Raised when the configured TLS cert/key pair cannot be used."""


# Seconds to allow for the TLS handshake on STARTTLS. Without this, a
# malicious peer can stall a worker thread indefinitely by opening a
# connection and never completing the handshake.
TLS_HANDSHAKE_TIMEOUT_SECONDS = 10

logger = logging.getLogger(__name__)

# Cap on accumulated SMTP message body size. Real spam fits comfortably
# under this; honeypot value drops fast above 1 MiB and unbounded reads
# turn into a denial-of-service vector.
MAX_MAIL_BODY_BYTES = 1_048_576

# End-of-data terminator per RFC 5321 §4.1.1.4. ``\A`` lets an empty
# body (``.\r\n`` immediately after the 354) terminate correctly. ``\r?``
# tolerates LF-only clients.
_DATA_TERMINATOR_RE = re.compile(rb"(?:\r?\n|\A)\.\r?\n")
# Maximum bytes of overlap to keep when searching across recv() boundaries.
_DATA_TERMINATOR_TAIL = 4

# Per-connection inactivity timeout, in seconds. Bounds how long a single
# client can hold a handler thread (and socket) while sending nothing —
# without it a slow-loris client pins threads indefinitely. A value <= 0
# disables the timeout.
DEFAULT_CONN_TIMEOUT = 30

# Cap on the number of command lines carried in the session_ended event.
# The count keeps going past this; only the list stops growing, so a
# client that pipes thousands of EHLOs cannot inflate a single log line.
MAX_LOGGED_COMMANDS = 200

def _auth_login_to_plain(user_b64: str, password_b64: str) -> str:
    """Combine the two AUTH LOGIN answers into the AUTH PLAIN blob.

    AUTH PLAIN carries ``base64("\\0user\\0password")`` on one line, so
    storing AUTH LOGIN captures in the same shape keeps every captured
    credential decodable the same way. If either part is not valid base64,
    fall back to ``user:password`` as received so nothing is lost.
    """
    try:
        user = base64.b64decode(user_b64, validate=True)
        password = base64.b64decode(password_b64, validate=True)
    except (binascii.Error, ValueError):
        return f"{user_b64}:{password_b64}"
    return base64.b64encode(b"\x00" + user + b"\x00" + password).decode()


class SMTPHoneypot:
    """
    SMTP Honeypot Server class
    """
    
    def __init__(
        self,
        bind_ip: str = '0.0.0.0',
        bind_port: int = 25,
        server_name: str = 'mail.example.com',
        mail_dir: Optional[str] = None,
        conn_timeout: int = DEFAULT_CONN_TIMEOUT,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
    ):
        """
        Initialize the SMTP honeypot server.

        Args:
            bind_ip: IP address to bind to
            bind_port: Port to listen on
            server_name: Server name to display in SMTP responses
            mail_dir: When set, captured message bodies are written to disk
                under this directory and the session log records the
                relative path. When None, bodies are discarded after
                metadata (size, truncated flag) is recorded — operators
                opt *in* to body retention rather than out of it.
            conn_timeout: Per-connection inactivity timeout in seconds. A
                client that sends nothing for this long is dropped, so a
                slow-loris client cannot pin a handler thread. A value
                <= 0 disables the timeout.
            tls_cert: Path to PEM cert/chain. Both ``tls_cert`` and
                ``tls_key`` must be provided to enable STARTTLS.
            tls_key: Path to PEM private key.
        """
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.server_name = server_name
        self.mail_dir = mail_dir
        self.conn_timeout = conn_timeout
        self.socket = None

        if tls_cert and tls_key:
            self.tls_context = self._build_tls_context(tls_cert, tls_key)
        else:
            # Half-configured (one of the two set) leaves TLS off. The
            # operator-facing warning for that lives in preflight_tls,
            # which runs before migrations reconfigure logging.
            self.tls_context = None

        # Pre-TLS EHLO advertises STARTTLS only when we can actually serve
        # it; post-TLS EHLO (sent after a successful upgrade) drops the
        # STARTTLS line per RFC 3207 §4.2.
        capabilities = ["PIPELINING", "SIZE 10240000", "VRFY", "ETRN"]
        if self.tls_context is not None:
            capabilities.append("STARTTLS")
        capabilities.extend(["AUTH LOGIN PLAIN", "8BITMIME"])
        self.ehlo_response = self._format_ehlo_response(capabilities)
        self.ehlo_response_post_tls = self._format_ehlo_response(
            [c for c in capabilities if c != "STARTTLS"]
        )

    def _format_ehlo_response(self, capabilities: List[str]) -> str:
        """Render an EHLO response with proper continuation markers.

        All lines except the last use ``250-`` as the prefix; the final
        line uses ``250 `` (space) per RFC 5321 §4.2.1.
        """
        lines = [self.server_name, *capabilities]
        formatted = []
        for i, line in enumerate(lines):
            sep = "-" if i < len(lines) - 1 else " "
            formatted.append(f"250{sep}{line}")
        return "\n".join(formatted) + "\n"

    @staticmethod
    def _build_tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
        """Build an SSLContext for STARTTLS upgrades.

        Pinned to TLS 1.2+ (1.0/1.1 are deprecated and offer no upside
        for a honeypot). Cert and key are loaded once at startup.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        except (OSError, ssl.SSLError) as e:
            raise TLSConfigError(
                f"could not load TLS cert/key pair "
                f"({cert_path!r}, {key_path!r}): {e}"
            ) from e
        return ctx
        
    def start(self) -> None:
        """
        Start the SMTP honeypot server.

        Supports IPv4 (e.g. ``0.0.0.0``), IPv6 (e.g. ``::1``), and
        dual-stack (``::``) bind addresses. Uses ``socket.create_server``
        so dual-stack mode works transparently when the platform allows.
        """
        try:
            if ":" in self.bind_ip:
                family = socket.AF_INET6
                # '::' is the IPv6 wildcard; pair it with dualstack_ipv6
                # so the listener also accepts IPv4-mapped connections.
                dualstack = (
                    self.bind_ip in ("::", "::0")
                    and socket.has_dualstack_ipv6()
                )
            else:
                family = socket.AF_INET
                dualstack = False

            self.socket = socket.create_server(
                (self.bind_ip, self.bind_port),
                family=family,
                backlog=10,
                dualstack_ipv6=dualstack,
            )
            
            logger.info(f"SMTP Honeypot listening on {self.bind_ip}:{self.bind_port}")
            print(f"[*] SMTP Honeypot listening on {self.bind_ip}:{self.bind_port}", file=sys.stderr)
            
            self._accept_connections()
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            if self.socket:
                self.socket.close()
            raise
    
    def _accept_connections(self) -> None:
        """
        Accept and handle incoming connections
        """
        while True:
            try:
                client, addr = self.socket.accept()
                logger.info(f"Connection from {addr[0]}:{addr[1]} to {self.bind_ip}:{self.bind_port}")
                print(f"[*] Connection from {addr[0]}:{addr[1]} to {self.bind_ip}:{self.bind_port}", file=sys.stderr)
                
                client_handler = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr)
                )
                client_handler.daemon = True
                client_handler.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                
    def _receive_mail_body(
        self,
        recv_fn,
        max_bytes: int = MAX_MAIL_BODY_BYTES,
    ) -> Tuple[bytes, bool]:
        """
        Read SMTP message body bytes after a 354 response.

        Reads via ``recv_fn(buffer_size)`` until the standard end-of-data
        terminator (``<CRLF>.<CRLF>`` or the permissive ``\\n.\\n``) is
        seen, or until ``max_bytes`` have been accumulated, or the peer
        closes the connection, or ``recv_fn`` raises ``socket.timeout``
        (the client stalled mid-body).

        The terminator search spans the chunk boundary by carrying over a
        small tail from the previous read, so a terminator that lands
        across two ``recv()`` calls is still detected.

        Returns:
            (body, terminator_found) — body excludes the terminator if
            one was matched. ``terminator_found`` is False for a peer
            close, a size-cap hit, or a recv timeout (truncated body).
        """
        body = bytearray()
        while len(body) < max_bytes:
            remaining = max_bytes - len(body)
            try:
                chunk = recv_fn(min(4096, remaining))
            except socket.timeout:
                # Client stalled mid-body. Return what arrived as a
                # truncated message rather than blocking the thread.
                break
            if not chunk:
                break
            search_start = max(0, len(body) - _DATA_TERMINATOR_TAIL)
            body.extend(chunk)
            m = _DATA_TERMINATOR_RE.search(bytes(body), search_start)
            if m:
                return bytes(body[:m.start()]), True
        return bytes(body), False

    def _handle_client(self, client_socket: socket.socket, addr: Tuple[str, int]) -> None:
        """
        Handle client connection.

        Binds the session UUID to the current execution context so every
        operational log record emitted from this thread carries it, then
        runs the SMTP conversation in ``_run_session``.

        Args:
            client_socket: Client socket
            addr: Client address tuple (ip, port)
        """
        session_uuid = str(uuid.uuid4())
        with events.session_context(session_uuid):
            self._run_session(client_socket, addr, session_uuid)

    def _run_session(
        self,
        client_socket: socket.socket,
        addr: Tuple[str, int],
        session_uuid: str,
    ) -> None:
        """
        Run one SMTP conversation to completion.

        Two records come out of every session:

        * the per-command transcript (``session_log``), stored in the
          database exactly as before, and
        * a flat summary (commands, credentials, mail metadata, outcome)
          emitted as a ``session_ended`` event for log shippers. The
          summary never carries message bodies.
        """
        metrics.CONNECTIONS_TOTAL.inc()
        metrics.ACTIVE_SESSIONS.inc()
        session_started_at = time.monotonic()
        session_outcome = "ok"
        session_record = None
        session_log = []

        events.session_started(
            session_uuid=session_uuid,
            src_ip=addr[0],
            src_port=addr[1],
            server_name=self.server_name,
            dest_ip=self.bind_ip,
            dest_port=self.bind_port,
        )

        # Summary state. ``commands`` is capped so a chatty client cannot
        # inflate the session_ended event without bound; ``command_count``
        # keeps counting past the cap.
        commands: List[str] = []
        command_count = 0
        commands_truncated = False
        credentials: List[str] = []
        mail: List[Dict[str, Any]] = []
        last_response_code: Optional[int] = None
        tls_version: Optional[str] = None
        tls_error: Optional[str] = None

        # Bound the lifetime of an idle connection. With a timeout set,
        # recv()/send() raise socket.timeout after this many seconds of
        # inactivity, so a client that connects and then sends nothing
        # (slow-loris) cannot pin this handler thread forever. A value
        # <= 0 leaves the socket in its default blocking mode.
        if self.conn_timeout and self.conn_timeout > 0:
            client_socket.settimeout(self.conn_timeout)
        tls_active = False

        def send(response: str) -> None:
            """Send a reply, record it in the transcript, track its code.

            Reads ``client_socket`` from the enclosing scope at call time,
            so it follows the rebinding to the SSLSocket after STARTTLS.
            """
            nonlocal last_response_code
            client_socket.send(response.encode())
            session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
            try:
                last_response_code = int(response[:3])
            except ValueError:
                pass

        try:
            # Inside the try so a database failure here still reaches the
            # finally block (metrics, session_ended event, socket close).
            session_record = create_session(
                addr[0], addr[1], self.server_name,
                dest_ip=self.bind_ip,
                dest_port=self.bind_port
            )

            # Send banner
            send(f"220 {self.server_name} ESMTP Service Ready\n")

            # Handle client commands
            error_count = 0
            # AUTH LOGIN is a two-step exchange: 0 = idle, 1 = waiting for
            # the username, 2 = waiting for the password.
            auth_login_state = 0
            auth_login_user = ""
            while error_count < 10:
                try:
                    # Keep the client's original text: credentials are base64,
                    # which is case-sensitive. Commands are matched on the
                    # lowercase copy.
                    request_raw = client_socket.recv(4096).decode().strip()
                    request = request_raw.lower()
                    if not request:
                        break

                    session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "in", "data": request})
                    command_count += 1
                    if len(commands) < MAX_LOGGED_COMMANDS:
                        commands.append(request)
                    else:
                        commands_truncated = True
                    logger.debug(f"Client: {request}")
                    metrics.COMMANDS_TOTAL.labels(
                        command=metrics.classify_command(request)
                    ).inc()

                    # Second and third lines of an AUTH LOGIN exchange. These
                    # are not commands, so they must be handled before the
                    # command matching below.
                    if auth_login_state == 1:
                        auth_login_user = request_raw
                        auth_login_state = 2
                        send("334 UGFzc3dvcmQ6\n")  # "Password:"
                        continue
                    if auth_login_state == 2:
                        auth_login_state = 0
                        auth_string = _auth_login_to_plain(auth_login_user, request_raw)
                        metrics.CREDENTIALS_CAPTURED_TOTAL.inc()
                        credentials.append(auth_string)
                        events.credential_captured(session_uuid, auth_string)
                        log_credential(session_record.id, auth_string)
                        logger.info(f"Captured credential: {auth_string}")
                        send("535 5.7.8 Authentication failed\n")
                        continue

                    # Handle EHLO/HELO. Use the post-TLS variant once a
                    # STARTTLS upgrade has succeeded (no STARTTLS line).
                    if request.startswith('ehlo') or request.startswith('helo'):
                        send(self.ehlo_response_post_tls if tls_active else self.ehlo_response)
                        error_count = 0

                    # STARTTLS — upgrade the connection in place.
                    elif request.startswith('starttls'):
                        if self.tls_context is None:
                            send("454 4.7.0 TLS not available\n")
                            error_count += 1
                        elif tls_active:
                            send("503 5.5.1 STARTTLS already active\n")
                            error_count += 1
                        else:
                            send("220 2.0.0 Ready to start TLS\n")
                            try:
                                client_socket.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
                                client_socket = self.tls_context.wrap_socket(
                                    client_socket,
                                    server_side=True,
                                )
                                # Restore the inactivity timeout the
                                # handshake temporarily widened. Clearing
                                # it outright would exempt every upgraded
                                # connection from slow-loris protection.
                                client_socket.settimeout(
                                    self.conn_timeout
                                    if self.conn_timeout and self.conn_timeout > 0
                                    else None
                                )
                                tls_active = True
                                tls_version = client_socket.version()
                                session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "tls-upgrade", "tls_version": tls_version})
                                error_count = 0
                            except (ssl.SSLError, OSError, socket.timeout) as e:
                                logger.warning(f"TLS handshake failed for {addr[0]}:{addr[1]}: {e}")
                                tls_error = str(e)
                                session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "tls-failed", "error": tls_error})
                                break

                    # Handle AUTH
                    elif request.startswith('auth login'):
                        parts = request_raw.split()
                        if len(parts) >= 3:
                            # Username sent on the same line: AUTH LOGIN <user>
                            auth_login_user = parts[2]
                            auth_login_state = 2
                            send("334 UGFzc3dvcmQ6\n")  # "Password:"
                        else:
                            auth_login_state = 1
                            send("334 VXNlcm5hbWU6\n")  # "Username:"

                    elif request.startswith('auth plain'):
                        # Extract auth string from the original-case text
                        parts = request_raw.split()
                        if len(parts) >= 3:
                            auth_string = parts[2]
                            metrics.CREDENTIALS_CAPTURED_TOTAL.inc()
                            credentials.append(auth_string)
                            events.credential_captured(session_uuid, auth_string)
                            log_credential(session_record.id, auth_string)
                            logger.info(f"Captured credential: {auth_string}")

                        send("535 5.7.8 Authentication failed\n")

                    # Handle QUIT
                    elif request.startswith('quit'):
                        send("221 2.0.0 Goodbye\n")
                        break

                    # MAIL FROM: / RCPT TO: — accept envelope, no body involved.
                    elif request.startswith(('mail from:', 'rcpt to:')):
                        send("250 2.1.0 OK\n")
                        error_count = 0

                    # DATA — enter body-receive mode, read until terminator
                    # or size cap, then return to command mode.
                    elif request.startswith('data'):
                        send("354 End data with <CR><LF>.<CR><LF>\n")

                        body, terminator_found = self._receive_mail_body(client_socket.recv)

                        # Metadata only; the same dict feeds the transcript
                        # entry and the summary's ``mail`` list.
                        body_meta: Dict[str, Any] = {
                            "size": len(body),
                            "truncated": not terminator_found,
                        }
                        if self.mail_dir:
                            try:
                                rel_path = store_mail_body(
                                    self.mail_dir, addr[0], session_uuid, body,
                                )
                                body_meta["body_path"] = rel_path
                            except OSError as e:
                                # Body storage was requested but failed. Log
                                # the underlying error and surface it on the
                                # record; do NOT inline the body bytes here —
                                # if the operator set MAIL_DIR they
                                # explicitly chose not to keep bodies in the
                                # log/DB/event stream, and an error path
                                # should not silently override that.
                                logger.error(f"Failed to write mail body: {e}")
                                body_meta["body_path_error"] = str(e)
                        # If self.mail_dir is unset, only metadata (size,
                        # truncated) is retained. Operators opt in to body
                        # retention by setting MAIL_DIR.
                        session_log.append({
                            "timestamp": strftime("%Y-%m-%d %H:%M:%S"),
                            "direction": "mail-body",
                            **body_meta,
                        })
                        mail.append(body_meta)

                        if terminator_found:
                            response = "250 2.0.0 Ok\n"
                        elif len(body) >= MAX_MAIL_BODY_BYTES:
                            response = "552 5.3.4 Message size limit exceeded\n"
                        else:
                            # Peer closed mid-body. Connection is effectively gone;
                            # send a polite close and break.
                            response = "421 4.4.2 Connection closed\n"
                        send(response)
                        if not terminator_found:
                            break
                        error_count = 0

                    # Unknown command
                    else:
                        send("502 5.5.2 Error: command not recognized\n")
                        error_count += 1

                except socket.timeout:
                    # Idle longer than conn_timeout. Drop the connection
                    # so the handler thread is freed; the 421 reply is
                    # best-effort since the peer may already be gone.
                    logger.info(
                        f"Connection from {addr[0]}:{addr[1]} timed out after "
                        f"{self.conn_timeout}s of inactivity"
                    )
                    try:
                        send("421 4.4.2 Connection timed out\n")
                    except OSError:
                        pass
                    # Distinct from "ok": an idle drop is not a session
                    # that ran to completion, and operators watching the
                    # metric want slow-loris pressure to be visible.
                    session_outcome = "timeout"
                    break

                except Exception as e:
                    logger.error(f"Error handling client request: {e}")
                    error_count += 1

        except Exception as e:
            logger.error(f"Error in client handler: {e}")
            session_outcome = "error"
        finally:
            duration = time.monotonic() - session_started_at
            metrics.SESSIONS_TOTAL.labels(result=session_outcome).inc()
            metrics.SESSION_DURATION_SECONDS.observe(duration)
            if command_count == 0:
                metrics.BANNER_ONLY_SESSIONS_TOTAL.inc()
            metrics.ACTIVE_SESSIONS.dec()

            summary: Dict[str, Any] = {
                "src_ip": addr[0],
                "src_port": addr[1],
                "dest_ip": self.bind_ip,
                "dest_port": self.bind_port,
                "duration_seconds": round(duration, 3),
                "command_count": command_count,
                "commands": commands,
                "last_response_code": last_response_code,
                "outcome": session_outcome,
            }
            if commands_truncated:
                summary["commands_truncated"] = True
            if session_outcome == "timeout":
                summary["timed_out"] = True
            if tls_version is not None:
                summary["tls_version"] = tls_version
            if tls_error is not None:
                summary["tls_error"] = tls_error
            if credentials:
                summary["credentials"] = credentials
            if mail:
                summary["mail"] = mail
                # Flat total so log queries (e.g. the Grafana dashboard's
                # "sessions with mail body" panel) can filter on it; nested
                # arrays are opaque to Loki's ``| json``.
                summary["mail_size"] = sum(m["size"] for m in mail)
            events.session_ended(session_uuid=session_uuid, summary=summary)

            # Store the transcript. Runs on every exit path (quit, timeout,
            # error) and must never prevent the socket from being closed.
            try:
                update_session_data(
                    session_record.id if session_record is not None else None,
                    json.dumps(session_log),
                )
            except Exception as e:
                logger.error(f"Failed to store session log: {e}")

            try:
                client_socket.close()
            except OSError:
                pass
            logger.info(f"Connection closed for {addr[0]}:{addr[1]} (dest: {self.bind_ip}:{self.bind_port})")

    def stop(self) -> None:
        """
        Stop the SMTP honeypot server
        """
        if self.socket:
            self.socket.close()
            logger.info("SMTP Honeypot server stopped")


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Mailoney - A Simple SMTP Honeypot")
    
    parser.add_argument(
        '-i', '--ip', 
        default=get_settings().bind_ip,
        help='IP address to bind to (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '-p', '--port', 
        type=int, 
        default=get_settings().bind_port,
        help='Port to listen on (default: 25)'
    )
    
    parser.add_argument(
        '-s', '--server-name', 
        default=get_settings().server_name,
        help='Server name to display in SMTP responses'
    )
    
    parser.add_argument(
        '-d', '--db-url',
        default=get_settings().db_url,
        help=(
            'Database URL (default: sqlite:///mailoney.db). '
            'Pass an empty string to disable the database and run in '
            'event-logging-only mode.'
        )
    )

    parser.add_argument(
        '--mail-dir',
        default=get_settings().mail_dir,
        help=(
            'Directory under which captured SMTP message bodies are written '
            'as <YYYY-MM-DD>/<src-ip>/<session>.eml. '
            'When unset, bodies stay inline in the session log.'
        )
    )

    parser.add_argument(
        '--tls-cert',
        default=get_settings().tls_cert,
        help=(
            'Path to a PEM cert/chain. Both --tls-cert and --tls-key '
            'must be set to enable STARTTLS.'
        )
    )

    parser.add_argument(
        '--conn-timeout',
        type=int,
        default=get_settings().conn_timeout,
        help=(
            'Per-connection inactivity timeout in seconds. A client that '
            'sends nothing for this long is dropped, bounding slow-loris '
            'style abuse. 0 disables it. (default: 30)'
        )
    )

    parser.add_argument(
        '--tls-key',
        default=get_settings().tls_key,
        help='Path to the PEM private key for --tls-cert.'
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default=get_settings().log_level,
        help='Log level'
    )

    parser.add_argument(
        '--log-json',
        action='store_true',
        default=get_settings().log_json,
        help=(
            'Emit every log line — both honeypot events and operational '
            'records — as JSON Lines on stdout. Default is human-readable '
            'text for both.'
        )
    )

    parser.add_argument(
        '--metrics-port',
        type=int,
        default=get_settings().metrics_port,
        help=(
            'Port to serve Prometheus /metrics on. '
            'If unset, the metrics endpoint is disabled.'
        )
    )

    parser.add_argument(
        '--metrics-bind',
        default=get_settings().metrics_bind,
        help=(
            'Bind address for the /metrics endpoint (default: 127.0.0.1, '
            'loopback only). Use 0.0.0.0 or :: to scrape from another host '
            'or container, and keep that port off any public interface.'
        )
    )

    return parser.parse_args()


def preflight_tls(tls_cert: Optional[str], tls_key: Optional[str]) -> None:
    """Validate the TLS configuration before any other startup work.

    Deliberately runs ahead of ``init_db``: a mistyped cert path should
    not surface as a database error, and writing to stderr keeps the
    message visible even though Alembic reconfigures logging while
    applying migrations.

    Exits with status 2 on a cert/key pair that is set but unusable —
    an operator who asked for TLS is better served by a hard failure
    than by a honeypot that quietly falls back to plaintext.
    """
    if not tls_cert and not tls_key:
        return

    if bool(tls_cert) != bool(tls_key):
        # Almost always a typo in one of the two env vars. Not fatal --
        # a honeypot should stay up -- but silence here would leave the
        # operator believing STARTTLS is live when it is not.
        missing = "key (MAILONEY_TLS_KEY)" if tls_cert else "cert (MAILONEY_TLS_CERT)"
        print(
            f"[!] STARTTLS: TLS {missing} is not set, so STARTTLS stays\n"
            "    disabled and the honeypot serves plaintext only. Both the\n"
            "    cert and the key are required to enable it.",
            file=sys.stderr,
        )
        return

    for label, path in (("cert", tls_cert), ("key", tls_key)):
        if not os.path.exists(path):
            print(
                f"[!] STARTTLS: TLS {label} not found: {path}",
                file=sys.stderr,
            )
            sys.exit(2)
        if not os.access(path, os.R_OK):
            print(
                f"[!] STARTTLS: TLS {label} is not readable: {path}\n"
                "    The container image runs as the unprivileged 'mailoney'\n"
                "    user. Certbot keys under /etc/letsencrypt/ and Debian's\n"
                "    snakeoil key are root-owned by default -- see the\n"
                "    STARTTLS section of the README for the usual fixes.",
                file=sys.stderr,
            )
            sys.exit(2)

    # Both readable: load them now so a malformed or mismatched pair is
    # reported here rather than as an opaque failure further in.
    try:
        SMTPHoneypot._build_tls_context(tls_cert, tls_key)
    except TLSConfigError as e:
        print(f"[!] STARTTLS: {e}", file=sys.stderr)
        sys.exit(2)


def display_banner() -> None:
    """Display the Mailoney banner"""
    from . import __version__
    
    banner = f"""
    ****************************************************************
    *    Mailoney - A Simple SMTP Honeypot - Version: {__version__}    *
    ****************************************************************
    """
    print(banner, file=sys.stderr)


def run_server() -> None:
    """
    Run the SMTP Honeypot server.
    This is the main entry point for the application.
    """
    # Parse command-line arguments
    args = parse_args()
    
    # Configure logging. The same flag drives both the operational
    # (root) logger and the events logger so the entire stdout stream
    # is uniformly text or uniformly JSON.
    configure_logging(args.log_level, json_format=args.log_json)
    events.init_event_logging(json_format=args.log_json)

    # Display banner (stderr, so stdout stays machine-readable)
    display_banner()

    # Validate TLS config before touching the database (see preflight_tls).
    preflight_tls(args.tls_cert, args.tls_key)

    # Initialize database (empty URL disables it; events still flow to logs).
    if args.db_url == "":
        logger.info("Database disabled; running in event-logging-only mode")
    else:
        logger.info(f"Initializing database with URL: {args.db_url}")
    init_db(args.db_url)

    # Alembic's fileConfig() runs inside init_db while applying migrations
    # and installs alembic.ini's own console handler on the root logger,
    # displacing the formatter chosen above. Re-apply it so JSON mode
    # survives a migration run.
    configure_logging(args.log_level, json_format=args.log_json)

    # Start Prometheus /metrics endpoint if requested
    if args.metrics_port:
        metrics.start_metrics_server(args.metrics_port, args.metrics_bind)

    # Create and start server
    try:
        server = SMTPHoneypot(
            bind_ip=args.ip,
            bind_port=args.port,
            server_name=args.server_name,
            mail_dir=args.mail_dir,
            conn_timeout=args.conn_timeout,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )
        
        logger.info(f"Starting SMTP Honeypot on {args.ip}:{args.port}")
        server.start()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Error running server: {e}")
        sys.exit(1)
