__author__ = '@awhitehatter'
__version__ = '0.1'

'''
add some nice comments here
'''

import argparse
import sys
import os
import modules.postfix_creds
import modules.open_relay

#parse the command line arguments to set the variables for the server
parser = argparse.ArgumentParser(description="Command line arguments")
parser.add_argument('-i',action='store', metavar='<ip address>', default='0.0.0.0', help='The IP address to listen on')
parser.add_argument('-p',action='store', metavar='<port>', default='25', help='The port to listen on')
parser.add_argument('-s',action='store', metavar='mailserver', required=True, help='A Name that\'ll show up as the mail server name')
parser.add_argument('-t',action='store', choices=['open_relay', 'postfix_creds'], required=True, help='honeypot type')
args = parser.parse_args()

#set the IP address variables
bind_ip = args.i
bind_port = int(args.p)
srvname = args.s

banner = ('''
****************************************************************
\tMailoney - A Simple SMTP Honeypot - Version: {}
****************************************************************
'''.format(__version__))

#create log directory (thanks @Bifrozt_Dev)
if not os.path.isdir('logs'):
        os.mkdir('logs')

#call server type module, based on parsed arguments
if args.t == 'postfix_creds':
    modules.postfix_creds.pfserver()

elif args.t == 'open_relay':
    modules.open_relay.or_module()
else:
    print 'I don\'t know what this module is...Exiting...\r\n'
