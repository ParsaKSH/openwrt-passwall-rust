# passwall2-rs: PassWall 2 with a Rust backend and a LuCI JS frontend.
# Build inside an OpenWrt SDK / buildroot (alternative to packaging/build.sh):
#
#   echo "src-git passwall2rs https://github.com/ParsaKSH/openwrt-passwall-rust.git" >> feeds.conf
#   ./scripts/feeds update -a && ./scripts/feeds install -a
#   make menuconfig   # LuCI -> Applications -> luci-app-passwall2-rs
#   make package/luci-app-passwall2-rs/compile V=s
#
# Produces: passwall2-rs (arch-specific Rust binary, needs rust/host from the packages feed),
# luci-app-passwall2-rs (arch all, via the standard luci.mk) and luci-i18n-passwall2-<lang>.
#
# Copyright (C) 2022-2025 xiaorouji
# Copyright (C) 2026 Openwrt-Passwall Organization
# Copyright (C) 2026 ParsaKSH
#
# This is free software, licensed under the GNU General Public License v3.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall2-rs
PKG_VERSION:=26.11.0
PKG_RELEASE:=1
PKG_PO_VERSION:=$(PKG_VERSION)
PKG_LICENSE:=GPL-3.0-only
PKG_MAINTAINER:=ParsaKSH <https://github.com/ParsaKSH>

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

# The Rust crate lives next to this directory in the repository (../passwall2). Resolve the
# feed symlink (package/feeds/<feed>/luci-app-passwall2 -> feeds/<feed>/luci-app-passwall2).
PW2_REPO_DIR:=$(abspath $(realpath $(CURDIR))/..)

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Haproxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Simple_Obfs \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Plugin

LUCI_TITLE:=LuCI support for PassWall 2 (Rust backend)
LUCI_DESCRIPTION:=Drop-in replacement for luci-app-passwall2 (same UCI configuration) with a Rust backend and a LuCI JS frontend.
LUCI_PKGARCH:=all
# Upstream LUCI_DEPENDS without the Lua runtime (libuci-lua lua luci-compat luci-lib-jsonc lyaml),
# plus the Rust backend.
LUCI_DEPENDS:=+passwall2-rs +luci-base +rpcd \
	+coreutils +coreutils-base64 +coreutils-nohup +coreutils-timeout +curl \
	+ip-full +resolveip +tcping \
	+geoview +v2ray-geoip +v2ray-geosite \
	+unzip

# luci.mk only forwards PKG_PROVIDES into the package definition; the second line injects
# CONFLICTS as well (the definition is eval'd line by line).
define PKG_PROVIDES
luci-app-passwall2
  CONFLICTS:=luci-app-passwall2
endef

define Package/$(PKG_NAME)/config
menu "Configuration"
	depends on PACKAGE_$(PKG_NAME)

choice
	prompt "Basic Core"
	default PACKAGE_$(PKG_NAME)_Basic_Core_All if aarch64||arm||i386||x86_64
	default PACKAGE_$(PKG_NAME)_Basic_Core_Xray

	config PACKAGE_$(PKG_NAME)_Basic_Core_Xray
		tristate "Xray"
		select PACKAGE_xray-core

	config PACKAGE_$(PKG_NAME)_Basic_Core_SingBox
		tristate "SingBox"
		select PACKAGE_sing-box

	config PACKAGE_$(PKG_NAME)_Basic_Core_All
		bool "All"
		select PACKAGE_xray-core
		select PACKAGE_sing-box
endchoice

config PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy
	bool "Iptables Transparent Proxy"
	select PACKAGE_chinadns-ng
	select PACKAGE_dnsmasq-full
	select PACKAGE_dnsmasq_full_ipset
	select PACKAGE_ipset
	select PACKAGE_iptables
	select PACKAGE_iptables-nft
	select PACKAGE_iptables-zz-legacy
	select PACKAGE_iptables-mod-conntrack-extra
	select PACKAGE_iptables-mod-extra
	select PACKAGE_iptables-mod-iprange
	select PACKAGE_iptables-mod-socket
	select PACKAGE_iptables-mod-tproxy
	select PACKAGE_ip6tables-mod-nat
	select PACKAGE_kmod-ipt-nat
	default y if ! PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy
	bool "Nftables Transparent Proxy"
	select PACKAGE_chinadns-ng
	select PACKAGE_dnsmasq-full
	select PACKAGE_dnsmasq_full_nftset
	select PACKAGE_nftables
	select PACKAGE_kmod-nft-socket
	select PACKAGE_kmod-nft-tproxy
	select PACKAGE_kmod-nft-nat
	default y if PACKAGE_firewall4

config PACKAGE_$(PKG_NAME)_INCLUDE_Haproxy
	bool "Include Haproxy"
	select PACKAGE_haproxy
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client
	bool "Include Shadowsocks Rust Client"
	depends on !i386
	select PACKAGE_shadowsocks-rust-sslocal
	default y if aarch64||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server
	bool "Include Shadowsocks Rust Server"
	depends on !i386
	select PACKAGE_shadowsocks-rust-ssserver
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client
	bool "Include ShadowsocksR Libev Client"
	select PACKAGE_shadowsocksr-libev-ssr-local
	select PACKAGE_shadowsocksr-libev-ssr-redir
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server
	bool "Include ShadowsocksR Libev Server"
	select PACKAGE_shadowsocksr-libev-ssr-server
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Simple_Obfs
	bool "Include Simple-Obfs (Shadowsocks Plugin)"
	select PACKAGE_simple-obfs-client
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Plugin
	bool "Include V2ray-Plugin (Shadowsocks Plugin)"
	select PACKAGE_v2ray-plugin
	default y if aarch64||arm||i386||x86_64

endmenu
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/passwall2
/etc/config/passwall2_server
/usr/share/passwall2/direct_ip
/usr/share/passwall2/domains_excluded
endef

# the backend's self-update writes progress files to passwall2-update/ (owned by no package):
# remove it with the package, keeping files younger than 5 minutes (an update in progress)
define Package/$(PKG_NAME)/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
d=/www/luci-static/resources/passwall2-update
[ -d "$$d" ] || exit 0
find "$$d" -type f -mmin +5 -exec rm -f {} + 2>/dev/null
rmdir "$$d" 2>/dev/null
exit 0
endef

# luci.mk copies htdocs/ and root/; add the Rust crate for passwall2-rs.
define Build/Prepare/luci-app-passwall2
	mkdir -p $(PKG_BUILD_DIR)/rust
	$(CP) $(PW2_REPO_DIR)/passwall2 $(PKG_BUILD_DIR)/rust/
	[ ! -f $(PW2_REPO_DIR)/Cargo.lock ] || $(CP) $(PW2_REPO_DIR)/Cargo.lock $(PKG_BUILD_DIR)/rust/passwall2/
endef

include $(TOPDIR)/feeds/luci/luci.mk

# ------------------------------------------------------------------ passwall2-rs (Rust binary)
RUST_PKG_LOCKED:=0
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/passwall2-rs
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=PassWall 2 backend (Rust)
  URL:=https://github.com/ParsaKSH/openwrt-passwall-rust
  DEPENDS:=$(RUST_ARCH_DEPENDS)
endef

define Package/passwall2-rs/description
  Service runtime, Xray/sing-box config generators, firewall, DNS, subscriptions
  and rpcd backend (/usr/bin/passwall2) for luci-app-passwall2-rs.
endef

define Package/passwall2-rs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/passwall2 $(1)/usr/bin/passwall2
endef

# the binary defines the rpcd method list of luci.passwall2: let rpcd re-read it
define Package/passwall2-rs/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	[ -x /usr/libexec/rpcd/luci.passwall2 ] && /etc/init.d/rpcd reload 2>/dev/null
	exit 0
}
endef

define Build/Compile
	$(call Build/Compile/Cargo,rust/passwall2)
endef

$(eval $(call BuildPackage,passwall2-rs))

# call BuildPackage - OpenWrt buildroot signature
