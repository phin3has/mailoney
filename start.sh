#!/bin/sh
# Run the honeypot under restricted privileges

if [[ $USER != "root" ]]; then
    echo "This script must be run as root!"
    exit 1
fi

display_usage() {
    echo -e "\nUsage: start.sh -s <fake mailserver name> -t <honeypot type> [Optional arguments] \n"
    echo "-s <fake mailserver name>	The name that will show up as the mail server name. (Example: -s mailserver)"
    echo "-t <honeypot type>		HoneyPot type. Choices:"
	echo "    postfix_creds 	Emulates PostFix authentication server, collects credentials"
	echo "    open_relay    	Emulates an open relay"
    echo "-i <ip address>		Optional argument - The IP address to listen on. (Default value is 0.0.0.0)"
    echo "-p <port>		Optional argument - The port to listen on. (Default value is 25)"
    echo -e "-h, --help		Show this help message and exit\n"
}

# check whether user had supplied -h or --help . If yes display usage
if [[ ( $# == "--help") ||  $# == "-h" ]] ; then
    display_usage
    exit 0
fi

# if less than 4 arguments supplied, display usage
if [  $# -le 3 ] ; then
    display_usage
    exit 1
fi

# put arguments into a variable
script_arguments=$@

echo "Starting mailoney in the background...\n"
cd $(dirname $0)
su mailoney -c "nohup authbind --deep python mailoney.py $script_arguments > $(dirname $0)/logs/mailoney.out &"
#There might be a better way to manage the background execution (on mailoney.py directly). nohup seems to have side effects on the logs.
