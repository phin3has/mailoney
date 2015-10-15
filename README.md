# About
Mailoney is a SMTP Honeypot I wrote just to have fun learning Python. The Open Relay module emulates an Open Relay and writes attempted emails to a log file. Similarly, the Authentication modules will capture credentials and write those to a log file. 

# Usage

You'll likely need to run this with elevated permissions as required to open sockets on special ports.

```
python mailoney.py -s mailbox <options>

  -h, --help            Show this help message and exit
  -i <ip address>       The IP address to listen on (defaults to localhost)
  -p <port>             The port to listen on (defaults to 25)
  -s mailserver         This will generate a fake hostname
  -t <type>		HoneyPot type
	open_relay	Emulates an open relay 
	postfix_creds   Emulates PostFix authentication server, collects credentials
                        
examples:
python mailoney.py -s mailbox -i 10.10.10.1 -p 990 -t postfix_creds

```

# ToDo 
 - [ ] Add modules for EXIM, Microsoft, others
 - [ ] Build in Error Handling
 - [ ] Add a Daemon flag to background process.
 - [ ] Secure this by not requiring elevated perms, port forward from port 25. 
 - [ ] Database logging
 - [ ] Possible relay for test emails. 
 - [ ] Make honeypot detection more difficult
 	(e.g. fuzz mailoney with SMTP commands, catch exceptions, patch and profit)

