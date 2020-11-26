#!/bin/bash
export DNSMASQ_INTERFACE=eth0
export DNSMASQ_TAGS=lan
export DNSMASQ_TIME_REMAINING=43200
export DNSMASQ_LEASE_EXPIRES=1605596290
export DNSMASQ_MUD_URL=https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json
export DNSMASQ_LOG_DHCP=1
export DNSMASQ_REQUESTED_OPTIONS=1,28,2,3,15,6,119,12,44,47,26,121,42
export DNSMASQ_SUPPLIED_HOSTNAME=64cb69b4591c

cargo run --bin namib_dnsmasq_hook add aa:bb:cc:dd:ee:ff 192.168.1.15 hostname
