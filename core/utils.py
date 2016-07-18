# this package contains some utilities such as logging and argument parsing

import argparse
import os
import sys
import sqlite3
from .ui import Colors


def menu():
    """Parses arguments from command line"""
    parser = argparse.ArgumentParser(description="Command line arguments")
    parser.add_argument('-i',action='store', metavar='<ip address>', default='0.0.0.0', help='The IP address to listen on')
    parser.add_argument('-p',action='store', metavar='<port>', default='25', help='The port to listen on')
    parser.add_argument('-s',action='store', metavar='mailserver', default="MAILSERVER-01", required=False, help='A Name that\'ll show up as the mail server name')
    parser.add_argument("--dangerzone", action="store_true", default=False, help="This passes information to a real SMTP server")

    return parser


def logger():
    """Creates Log directory and setups sqlite database"""
    if not os.path.isdir('logs'):
        os.mkdir('logs')

    os.chdir('logs')

    # Setting up DB parameters
    conn = sqlite3.connect('logs.db')

    c = conn.cursor()

    # Create table
    c.execute('''CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY , time VARCHAR(20), ip VARCHAR(16), port VARCHAR(8), data BLOB)''')

    conn.commit()
    conn.close()





def dangerzone_warning():
    """Warning Banner for Dangerzone"""
    print(Colors.R + """\tWARNING! You have enabled Dangerzone \n
    Dangerzone may pass SPAM and Malicious emails to your mailserver!!! \n
    Use at your own risk!!
    """ + Colors.W)


def dangerzone_confirm():
    confirm = input(Colors.R + "Are you sure you want to continue? [y/N]: " + Colors.W)

    if confirm.lower() == 'n' or confirm == '':
        print(Colors.R + "Exiting... \n" + Colors.W)
        sys.exit(0)
    elif confirm.lower() == 'y':
        dangerzone_auth()
    else:
        print(Colors.O + "Response not recognized. Exiting" + Colors.W)
        sys.exit(1)


def dangerzone_auth():
    #TODO Connect to SMTP server
    return None




