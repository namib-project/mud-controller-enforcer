FROM openwrtorg/rootfs:x86_64-21.02.3

ADD output/ /tmp/

RUN mkdir -p /var/lock && \
    opkg update && \
    opkg remove dnsmasq odhcpd-ipv6only && \
    opkg install /tmp/dnsmasq-full_*.ipk && \
    opkg install /tmp/namib_*.ipk && \
    rm -rf /tmp/*

ADD namib_enforcer/openwrt/image/network /etc/config/network
ADD namib_enforcer/openwrt/image/50_load_iptables /lib/preinit/50_load_iptables
ADD namib_enforcer/openwrt/image/inittab /etc/inittab

RUN mkdir -p /var/lock && /etc/init.d/sysntpd disable
