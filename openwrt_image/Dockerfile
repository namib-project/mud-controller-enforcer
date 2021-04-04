FROM scratch

ADD rootfs/ /
ADD openwrt_image/network /etc/config/network
ADD openwrt_image/50_load_iptables /lib/preinit/50_load_iptables
ADD openwrt_image/inittab /etc/inittab
USER root

RUN mkdir /var/lock && /etc/init.d/sysntpd disable

CMD ["/sbin/init"]