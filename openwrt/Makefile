# you must set $RUST_TRIPLE in your env
include $(TOPDIR)/rules.mk

PKG_NAME:=namib
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/namib
  SECTION:=net
  CATEGORY:=Utilities
  SUBMENU:=NAMIB
  TITLE:=NAMIB Enforcer
  URL:=https://gitlab.informatik.uni-bremen.de/namib/mud-controller-enforcer/namib_enforcer
  MAINTAINER:=Benjamin Ludewig <ludewigb@uni-bremen.de>
  DEPENDS:=@IPV6 +libavahi-compat-libdnssd +libuci
  PKG_BUILD_DEPENDS:=openssl
endef

define Package/namib/description
  NAMIB Enforcer
endef

ifeq ($(ARCH),arm)
	CROSS_PREFIX:=arm-openwrt-linux-muslgnueabi
	TARGET_LD:=arm-openwrt-linux-muslgnueabi-ld
	TARGET_AR:=arm-openwrt-linux-muslgnueabi-ar
else ifeq ($(ARCH),mips)
	CROSS_PREFIX:=mips-openwrt-linux-musl
	TARGET_LD:=mips-openwrt-linux-musl-ld
	TARGET_AR:=mips-openwrt-linux-musl-ar
else ifeq ($(ARCH),mips64)
	CROSS_PREFIX:=mips64-openwrt-linux
	TARGET_LD:=mips64-openwrt-linux-ld
	TARGET_AR:=mips64-openwrt-linux-ar
else ifeq ($(ARCH),mipsel)
	CROSS_PREFIX:=mipsel-openwrt-linux-musl
	TARGET_LD:=mipsel-openwrt-linux-musl-ld
	TARGET_AR:=mipsel-openwrt-linux-musl-ar
else ifeq ($(ARCH),x86_64)
	CROSS_PREFIX:=x86_64-openwrt-linux-musl
	TARGET_LD:=x86_64-openwrt-linux-musl-ld
	TARGET_AR:=x86_64-openwrt-linux-musl-ar
endif

NAMIB_PATH:="$(PKG_BUILD_DIR)/namib_enforcer/target/$(RUST_TRIPLE)/release/namib_enforcer"
NAMIB_HOOK_PATH:="$(PKG_BUILD_DIR)/namib_enforcer/target/$(RUST_TRIPLE)/release/namib_dnsmasq_hook"

define Build/Compile
	(\
		cd $(PKG_BUILD_DIR)/namib_enforcer && \
\
		OPENSSL_DIR=$(STAGING_DIR)/usr/ \
		OPENSSL_STATIC=1 \
		UCI_DIR=$(STAGING_DIR)/usr \
		RUSTFLAGS="-C linker=$(TARGET_CC_NOCACHE) -C ar=$(TARGET_AR) -C target-feature=-crt-static" \
		TARGET=$(RUST_TRIPLE) \
		TARGET_CC=$(TARGET_CC_NOCACHE) \
		TARGET_CXX=$(TARGET_CXX_NOCACHE) \
		PKG_CONFIG_ALLOW_CROSS=1 \
		CROSS_COMPILE=$(CROSS_PREFIX) \
\
		cargo build --release --target $(RUST_TRIPLE) --features="dnsmasq_hook" --bin namib_enforcer --bin namib_dnsmasq_hook \
	)
endef

define Package/namib/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(NAMIB_PATH) $(1)/usr/sbin/namib_enforcer
	$(INSTALL_BIN) $(NAMIB_HOOK_PATH) $(1)/usr/sbin/namib_dnsmasq_hook
	$(INSTALL_DIR) $(1)/etc/hotplug.d/dhcp
	$(INSTALL_BIN) ./files/namib.hook $(1)/etc/hotplug.d/dhcp/namib
	$(INSTALL_DIR) $(1)/etc/namib
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/namib_enforcer/certs/identity.pfx $(1)/etc/namib/identity.pfx
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/namib_enforcer/certs/namib-ca.pem $(1)/etc/namib/ca.pem
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/namib.init $(1)/etc/init.d/namib
	$(INSTALL_BIN) ./files/60-dnsmasq-enable-query-logs.sh $(1)/etc/uci-defaults/60-dnsmasq-enable-query-logs.sh
endef

$(eval $(call BuildPackage,namib))
