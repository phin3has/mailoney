__author__ = '@awhitehatter'

'''
Open relay module, will dump emails into a message log file

Thanks to:
https://djangosnippets.org/snippets/96/
https://muffinresearch.co.uk/fake-smtp-server-with-python/ (@muffinresearch)
'''

import sys
import os
import asyncore
from smtpd import SMTPServer

def or_module():

    class OpenRelay(SMTPServer):

        def process_message(self, peer, mailfrom, rcpttos, data):
            #setup the Log File
            if os.path.exists('logs/mail.log'):
                logfile = open('logs/mail.log', 'a')
            else:
                logfile = open('logs/mail.log', 'w')
            logfile.write('\n\n' + '*' * 50 + '\n')
            logfile.write('IP Address: {}\n'.format(peer[0]))
            logfile.write('Mail to: {}\n'.format(mailfrom))
            #Need to loop through rcpts if more than one is given
            logfile.write('Mail from: {}\n'.format(rcpttos[0]))
            logfile.write('Data:\n')
            logfile.write('\n')
            logfile.write(data.decode("utf-8"))
            logfile.close

    def run():
        sys.path.append("../")
        import mailoney

        honeypot = OpenRelay((mailoney.bind_ip, mailoney.bind_port), None)
        print('[*] Mail Relay listening on {}:{}'.format(mailoney.bind_ip, mailoney.bind_port))
        try:
            asyncore.loop()
        except KeyboardInterrupt:
            print('Detected interruption, terminating...')
    run()
