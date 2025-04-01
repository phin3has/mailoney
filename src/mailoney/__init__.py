"""
Mailoney - A Simple SMTP Honeypot
"""
__author__ = 'awhitehatter'
__version__ = '0.2.0'

from .db import init_db
from .server import SMTPHoneypot

def main():
    """Main entry point for the application."""
    from main.main_guts_stuff import run_server
    run_server()
