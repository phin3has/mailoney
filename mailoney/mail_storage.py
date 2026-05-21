"""
Filesystem storage for captured SMTP message bodies.

When ``MAILONEY_MAIL_DIR`` is set, each captured body is written to:

    <MAIL_DIR>/<YYYY-MM-DD>/<src-ip>/<session-uuid>.eml

The session record in the DB and the event log carry the *relative* path
(e.g. ``2026-05-09/2001:db8::1/abc-...eml``) instead of the body bytes,
keeping operational data small and letting bodies be handled like any
other file by mail/forensics tooling.

IPv6 source IPs land in folder names with their colons intact.
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _safe_ip_segment(src_ip: str) -> str:
    """Render a source IP as a directory name, defensively.

    IPv4 and IPv6 literals (with optional %zone) only contain digits,
    letters, ``.``, ``:``, ``%``, and ``-``. Whitelist those and drop
    anything else — defence in depth against malformed peer addresses,
    not a strict validator.
    """
    cleaned = "".join(c for c in src_ip if c.isalnum() or c in ".:%_-")
    return cleaned or "unknown"


def _today_segment() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def store_mail_body(
    mail_dir: str,
    src_ip: str,
    session_uuid: str,
    body: bytes,
) -> str:
    """
    Persist a captured mail body to disk.

    Args:
        mail_dir: Root directory (e.g. value of MAILONEY_MAIL_DIR).
        src_ip: Source IP literal of the SMTP client.
        session_uuid: Per-session identifier; used as the filename stem.
        body: Raw body bytes as captured between ``354`` and the
            ``<CRLF>.<CRLF>`` terminator (terminator already stripped).

    Returns:
        The path to the written file, relative to ``mail_dir``.
        Callers should record this in the session log so consumers know
        where to find the body.
    """
    root = Path(mail_dir)
    rel_dir = Path(_today_segment()) / _safe_ip_segment(src_ip)
    abs_dir = root / rel_dir
    abs_dir.mkdir(parents=True, exist_ok=True, mode=0o750)

    rel_path = rel_dir / f"{session_uuid}.eml"
    abs_path = root / rel_path

    # Open with O_CREAT|O_WRONLY|O_EXCL is safer (rejects collisions) but
    # session UUIDs are unique enough; use plain write for simplicity.
    with open(abs_path, "wb") as f:
        f.write(body)
    os.chmod(abs_path, 0o640)

    logger.info(f"Stored mail body ({len(body)} bytes) at {rel_path}")
    return str(rel_path)
