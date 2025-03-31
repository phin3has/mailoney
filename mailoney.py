#!/usr/bin/env python3
"""
Mailoney - A Simple SMTP Honeypot

This is the entry point script for running the Mailoney honeypot.
"""

import sys
import os

# Ensure the package is in the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    from main.main_guts_stuff import run_server
    run_server()
