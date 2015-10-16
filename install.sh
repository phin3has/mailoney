#!/bin/bash
# installation under restricted privileges
set -e
set -x

apt-get update
apt-get -y install python2.7 git authbind sudo

# Create Mailoney user
useradd -d /home/mailoney -s /bin/bash -m mailoney -g users

# Get the Mailoney source
cd /opt/
sudo git clone https://github.com/awhitehatter/mailoney.git
cd mailoney/

# Fix permissions for mailoney
chown -R mailoney:users /opt/mailoney
touch /etc/authbind/byport/25
chown mailoney /etc/authbind/byport/25
chmod 777 /etc/authbind/byport/25

echo "Mailoney has been installed in /opt/mailoney/"
echo "Please refer to start.sh to launch the honeypot"
