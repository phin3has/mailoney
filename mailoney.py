__author__ = '@awhitehatter'
__version__ = '0.1'

'''
add some nice comments here
'''

import argparse
import os
import hpfeeds
import modules.postfix_creds
import modules.open_relay
import modules.schizo_open_relay


# parse the command line arguments to set the variables for the server
parser = argparse.ArgumentParser(description="Command line arguments")
parser.add_argument('-i',action='store', metavar='<ip address>', default='0.0.0.0', help='The IP address to listen on')
parser.add_argument('-p',action='store', metavar='<port>',  default='25', help='The port to listen on')
parser.add_argument('-s',action='store', metavar='mailserver', default=os.environ.get('MAILSERVER_NAME', None), help='A Name that\'ll show up as the mail server name')
parser.add_argument('-t',action='store', choices=['open_relay', 'postfix_creds', 'schizo_open_relay'], required=True, help='honeypot type')
parser.add_argument('-logpath',action='store', metavar='<logpath>',  default=os.environ.get('LOGPATH'), help='path for file logging')
parser.add_argument('-hpfserver', action='store', metavar='<hpfeeds-server>', default=os.environ.get('HPFEEDS_SERVER', None), help='HPFeeds Server')
parser.add_argument('-hpfport', action='store', metavar='<hpfeeds-port>', default=os.environ.get('HPFEEDS_PORT', None), help='HPFeeds Port')
parser.add_argument('-hpfident', action='store', metavar='<hpfeeds-ident>', default=os.environ.get('HPFEEDS_IDENT', None), help='HPFeeds Username')
parser.add_argument('-hpfsecret', action='store', metavar='<hpfeeds-secret>', default=os.environ.get('HPFEEDS_SECRET', None), help='HPFeeds Secret')
parser.add_argument('-hpfchannelprefix', action='store', metavar='<hpfeeds-channel-prefix>', default=os.environ.get('HPFEEDS_CHANNELPREFIX', None), help='HPFeeds Channel Prefix')

args = parser.parse_args()

# set own logpath
logpath="./logs/"
if args.logpath:
    logpath=args.logpath

# set the IP address variables
bind_ip = args.i
bind_port = int(args.p)
srvname = args.s

def connect_hpfeeds():
    # set hpfeeds related data
    hpfeeds_server = args.hpfserver
    hpfeeds_port = args.hpfport
    hpfeeds_ident = args.hpfident
    hpfeeds_secret = args.hpfsecret
    hpfeeds_prefix = args.hpfchannelprefix

    if hpfeeds_server and hpfeeds_port and hpfeeds_ident and hpfeeds_secret and hpfeeds_prefix:
        try:
            hpc = hpfeeds.new(hpfeeds_server, int(hpfeeds_port), hpfeeds_ident, hpfeeds_secret)
            return hpc, hpfeeds_prefix
        except (hpfeeds.FeedException, socket.error, hpfeeds.Disconnect) as e:
            print("hpfeeds connection not successful")
            logger.warn('Exception while connecting: {0}'.format(e))
    return False, False


if __name__ == "__main__":

    banner = ('''
    ****************************************************************
    \tMailoney - A Simple SMTP Honeypot - Version: {}
    ****************************************************************
    '''.format(__version__))
    print(banner)

    # create log directory (thanks @Bifrozt_Dev)
    if not os.path.isdir(logpath):
            os.mkdir(logpath)

    # call server type module, based on parsed arguments
    if args.t == 'postfix_creds':
        modules.postfix_creds.pfserver()
    elif args.t == 'open_relay':
        modules.open_relay.or_module()
    elif args.t == 'schizo_open_relay':
        modules.schizo_open_relay.module()
    else:
        print('I don\'t know what this module is...Exiting...\r\n')

