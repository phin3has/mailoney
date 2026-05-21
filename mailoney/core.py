"""
Core functionality for the Mailoney SMTP Honeypot
"""
import re
import socket
import threading
import logging
import json
import sys
import uuid
import argparse
from time import strftime
from typing import Optional, Tuple, Dict, Any, List

from .db import create_session, update_session_data, log_credential, init_db
from .config import get_settings, configure_logging
from .mail_storage import store_mail_body

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
        """
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.server_name = server_name
        self.mail_dir = mail_dir
        self.socket = None
        self.ehlo_response = f'''250 {server_name}
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-AUTH LOGIN PLAIN
250 8BITMIME\n'''
        
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
            print(f"[*] SMTP Honeypot listening on {self.bind_ip}:{self.bind_port}")
            
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
                print(f"[*] Connection from {addr[0]}:{addr[1]} to {self.bind_ip}:{self.bind_port}")
                
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
        closes the connection.

        The terminator search spans the chunk boundary by carrying over a
        small tail from the previous read, so a terminator that lands
        across two ``recv()`` calls is still detected.

        Returns:
            (body, terminator_found) — body excludes the terminator if
            one was matched.
        """
        body = bytearray()
        while len(body) < max_bytes:
            remaining = max_bytes - len(body)
            chunk = recv_fn(min(4096, remaining))
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
        Handle client connection

        Args:
            client_socket: Client socket
            addr: Client address tuple (ip, port)
        """
        session_uuid = str(uuid.uuid4())
        session_record = create_session(
            addr[0], addr[1], self.server_name,
            dest_ip=self.bind_ip,
            dest_port=self.bind_port
        )
        session_log = []
        
        try:
            # Send banner
            banner = f"220 {self.server_name} ESMTP Service Ready\n"
            client_socket.send(banner.encode())
            session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": banner})
            
            # Handle client commands
            error_count = 0
            while error_count < 10:
                try:
                    request = client_socket.recv(4096).decode().strip().lower()
                    if not request:
                        break
                        
                    session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "in", "data": request})
                    logger.debug(f"Client: {request}")
                    
                    # Handle EHLO/HELO
                    if request.startswith('ehlo') or request.startswith('helo'):
                        client_socket.send(self.ehlo_response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": self.ehlo_response})
                        error_count = 0  # Reset error count after successful command
                        
                    # Handle AUTH
                    elif request.startswith('auth plain'):
                        # Extract auth string
                        parts = request.split()
                        if len(parts) >= 3:
                            auth_string = parts[2]
                            log_credential(session_record.id, auth_string)
                            logger.info(f"Captured credential: {auth_string}")
                            
                        response = "235 2.7.0 Authentication failed\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        
                    # Handle QUIT
                    elif request.startswith('quit'):
                        response = "221 2.0.0 Goodbye\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        break
                        
                    # MAIL FROM: / RCPT TO: — accept envelope, no body involved.
                    elif request.startswith(('mail from:', 'rcpt to:')):
                        response = "250 2.1.0 OK\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        error_count = 0

                    # DATA — enter body-receive mode, read until terminator
                    # or size cap, then return to command mode.
                    elif request.startswith('data'):
                        invitation = "354 End data with <CR><LF>.<CR><LF>\n"
                        client_socket.send(invitation.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": invitation})

                        body, terminator_found = self._receive_mail_body(client_socket.recv)

                        body_entry: Dict[str, Any] = {
                            "timestamp": strftime("%Y-%m-%d %H:%M:%S"),
                            "direction": "mail-body",
                            "size": len(body),
                            "truncated": not terminator_found,
                        }
                        if self.mail_dir:
                            try:
                                rel_path = store_mail_body(
                                    self.mail_dir, addr[0], session_uuid, body,
                                )
                                body_entry["body_path"] = rel_path
                            except OSError as e:
                                # Body storage was requested but failed. Log
                                # the underlying error and surface it on the
                                # record; do NOT inline the body bytes here —
                                # if the operator set MAIL_DIR they
                                # explicitly chose not to keep bodies in the
                                # log/DB stream, and an error path should not
                                # silently override that.
                                logger.error(f"Failed to write mail body: {e}")
                                body_entry["body_path_error"] = str(e)
                        # If self.mail_dir is unset, only metadata (size,
                        # truncated) is retained. Operators opt in to body
                        # retention by setting MAIL_DIR.
                        session_log.append(body_entry)

                        if terminator_found:
                            response = "250 2.0.0 Ok\n"
                        elif len(body) >= MAX_MAIL_BODY_BYTES:
                            response = "552 5.3.4 Message size limit exceeded\n"
                        else:
                            # Peer closed mid-body. Connection is effectively gone;
                            # send a polite close and break.
                            response = "421 4.4.2 Connection closed\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        if not terminator_found:
                            break
                        error_count = 0

                    # Unknown command
                    else:
                        response = "502 5.5.2 Error: command not recognized\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        error_count += 1
                        
                except Exception as e:
                    logger.error(f"Error handling client request: {e}")
                    error_count += 1
            
            # Store the session log
            update_session_data(session_record.id, json.dumps(session_log))
            
        except Exception as e:
            logger.error(f"Error in client handler: {e}")
        finally:
            client_socket.close()
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
        help='Database URL (default: sqlite:///mailoney.db)'
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
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default=get_settings().log_level,
        help='Log level'
    )

    return parser.parse_args()


def display_banner() -> None:
    """Display the Mailoney banner"""
    from . import __version__
    
    banner = f"""
    ****************************************************************
    *    Mailoney - A Simple SMTP Honeypot - Version: {__version__}    *
    ****************************************************************
    """
    print(banner)


def run_server() -> None:
    """
    Run the SMTP Honeypot server.
    This is the main entry point for the application.
    """
    # Parse command-line arguments
    args = parse_args()
    
    # Configure logging
    configure_logging(args.log_level)
    
    # Display banner
    display_banner()
    
    # Initialize database
    logger.info(f"Initializing database with URL: {args.db_url}")
    init_db(args.db_url)
    
    # Create and start server
    try:
        server = SMTPHoneypot(
            bind_ip=args.ip,
            bind_port=args.port,
            server_name=args.server_name,
            mail_dir=args.mail_dir,
        )
        
        logger.info(f"Starting SMTP Honeypot on {args.ip}:{args.port}")
        server.start()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Error running server: {e}")
        sys.exit(1)
