"""
Mailoney - A Simple SMTP Honeypot with database logging
"""
__author__ = 'awhitehatter'
__version__ = '2.1.0'

# Import key components to make them available at package level
from .db import init_db
from .core import SMTPHoneypot, run_server
from .config import get_settings, configure_logging
