FROM scratch

ADD rootfs/ /
ADD openwrt/image/network /etc/config/network
ADD openwrt/image/50_load_iptables /lib/preinit/50_load_iptables
ADD openwrt/image/inittab /etc/inittab
USER root

RUN mkdir /var/lock && /etc/init.d/sysntpd disable

CMD ["/sbin/init"]