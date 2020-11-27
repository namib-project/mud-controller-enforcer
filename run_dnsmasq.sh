#!/usr/bin/env bash

docker run --cap-add net_admin --rm -it -v $PWD/target/debug/namib_dnsmasq_hook:/etc/namib_dnsmasq_hook \
    -v /tmp/namib_dhcp2.sock:/tmp/namib_dhcp2.sock gitlab.informatik.uni-bremen.de:5005/namib/mud-controller-enforcer/dnsmasq:latest \
    dnsmasq -k --log-facility=- --dhcp-script=/etc/namib_dnsmasq_hook --log-dhcp --dhcp-authoritative --dhcp-range=172.17.0.100,172.17.0.200,12h