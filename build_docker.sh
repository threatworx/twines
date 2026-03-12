#!/bin/bash

# Install zeek
apt-get install -y --no-install-recommends g++ cmake make libpcap-dev
echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
apt update -y
apt-get install -y vim cron wireshare-common
apt install -y zeek-7.0 
export PATH=/opt/zeek/bin:$PATH

# Install app dependencies
pip3 install zkg
pip3 install mac-vendor-lookup

# ARP logging
zkg install zeek/corelight/zeek-community-id --force

# BACnet protocol analyzer
zkg install icsnpp-bacnet --force

# Modbus protocol analyzer
zkg install icsnpp-modbus --force

rm -f /tmp/*
