__author__ = '@awhitehatter'

'''
Module supports the main project file.
'''

import socket
import threading
import sys
import os
from time import strftime

def pfserver():
    sys.path.append("../")
    import mailoney

    print(mailoney.banner)
    # moving this below to see if this fixes the reconnection error
    # server set up
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((mailoney.bind_ip, mailoney.bind_port))
    server.listen(10)

    # setup the Postfix EHLO Response
    ehlo = '''250 {}
    250-PIPELINING
    250-SIZE 10240000
    250-VRFY
    250-ETRN
    250-STARTTLS
    250-AUTH LOGIN PLAIN
    250 8BITMIME\n'''.format(mailoney.srvname)

    #setup the Log File
    if os.path.exists('logs/credentials.log'):
        logfile = open('logs/credentials.log', 'a')
    else:
        logfile = open('logs/credentials.log', 'w')

    print(('[*] SMTP Server listening on {}:{}'.format(mailoney.bind_ip, mailoney.bind_port)))

    def handle_client(client_socket):
        # Send banner
        client_socket.send('220 {} ESMTP Postfix\n'.format(mailoney.srvname))

        while True:

            # Setup a loop to communicate with the client
            count = 0
            while count < 10:
                request=client_socket.recv(4096).lower()

                if 'ehlo' in request:
                    client_socket.send(ehlo)
                    break
                else:
                    client_socket.send('502 5.5.2 Error: command not recognized\n')
                    count += 1

            #kill the client for too many errors
            if count == 10:
                client_socket.send('421 4.7.0 {} Error: too many errors\n'.format(mailoney.srvname))
                client_socket.close()
                break

            #reset the counter and hope for creds
            count = 0
            while count < 10:
                request = client_socket.recv(4096).lower()

                if 'auth plain' in request:
                    #pull the base64 string and validate
                    auth = request.split(' ')[2]
                    timestamp = strftime("%Y-%m-%d %H:%M:%S")
                    logfile.write('{}\tIP_Address: {}\tAuth: {}'.format(timestamp, addr[0], auth))
                    client_socket.send('235 2.0.0 Authentication Failed\n')

                elif 'exit' in request:
                    count = 10
                    break
                else:
                    client_socket.send('502 5.5.2 Error: command not recognized\n')
                    count += 1

            #kill the connection for too many failures
            if count == 10:
                client_socket.send('421 4.7.0 {} Error: too many errors\n'.format(mailoney.srvname))
                client_socket.close()
                break

            # reset the count
            count = 0

    while True:

        client,addr = server.accept()

        print("[*] Accepted connection from {}:{}".format(addr[0],addr[1]))

        # now handle client data
        client_handler = threading.Thread(target=handle_client(client,))
        client_handler.start()
