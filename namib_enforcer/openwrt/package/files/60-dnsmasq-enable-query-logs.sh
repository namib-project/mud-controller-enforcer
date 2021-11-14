uci set dhcp.@dnsmasq[0].logqueries='1'
uci set dhcp.@dnsmasq[0].logfacility='/tmp/dnsmasq.log'
uci set dhcp.@dnsmasq[0].dhcpscript='/usr/lib/namib/dnsmasq_hook.sh'
uci commit