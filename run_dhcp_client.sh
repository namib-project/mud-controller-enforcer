#!/usr/bin/env bash

docker run --rm -it debian

apt-get update && apt-get install isc-dhcp-client

echo 'option mudurl code 161 = text;' >> /etc/dhcp/dhclient.conf
echo 'send mudurl "https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json";' >> /etc/dhcp/dhclient.conf
dhclient -1 -4 -d
