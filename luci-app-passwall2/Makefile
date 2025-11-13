# Copyright (C) 2022-2025 xiaorouji
#
# This is free software, licensed under the GNU General Public License v3.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall2
PKG_VERSION:=25.11.14
PKG_RELEASE:=1
PKG_PO_VERSION:=$(PKG_VERSION)

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Iptables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_Nftables_Transparent_Proxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Haproxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_IPv6_Nat \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Rust_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_ShadowsocksR_Libev_Server \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_Simple_Obfs \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_SingBox \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_tuic_client \
	CONFIG_PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Plugin

LUCI_TITLE:=LuCI support for PassWall 2
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+coreutils +coreutils-base64 +coreutils-nohup +curl \
	+ip-full +libuci-lua +lua +luci-compat +luci-lib-jsonc +resolveip +tcping \
	+xray-core +geoview +v2ray-geoip +v2ray-geosite \
	+unzip \
	+PACKAGE_$(PKG_NAME)_INCLUDE_IPv6_Nat:ip6tables-mod-nat

define Package/$(PKG_NAME)/config
menu "Configuration"

config PACKAGE_$(PKG_NAME)_INCLUDE_IPv6_Nat
	depends on PACKAGE_ip6tables
	bool "Include IPv6 Nat"
	default n

if PACKAGE_$(PKG_NAME)

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
	select PACKAGE_iptables-mod-iprange
	select PACKAGE_iptables-mod-socket
	select PACKAGE_iptables-mod-tproxy
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

config PACKAGE_$(PKG_NAME)_INCLUDE_Hysteria
	bool "Include Hysteria"
	select PACKAGE_hysteria
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_NaiveProxy
	bool "Include NaiveProxy"
	depends on !(arc||armeb||loongarch64||mips||mips64||powerpc||TARGET_gemini)
	select PACKAGE_naiveproxy
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Client
	bool "Include Shadowsocks Libev Client"
	select PACKAGE_shadowsocks-libev-ss-local
	select PACKAGE_shadowsocks-libev-ss-redir
	default y

config PACKAGE_$(PKG_NAME)_INCLUDE_Shadowsocks_Libev_Server
	bool "Include Shadowsocks Libev Server"
	select PACKAGE_shadowsocks-libev-ss-server
	default n

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

config PACKAGE_$(PKG_NAME)_INCLUDE_SingBox
	bool "Include Sing-Box"
	select PACKAGE_sing-box
	default y if aarch64||arm||i386||x86_64

config PACKAGE_$(PKG_NAME)_INCLUDE_tuic_client
	bool "Include tuic-client"
	depends on aarch64||arm||i386||x86_64
	select PACKAGE_tuic-client
	default n

config PACKAGE_$(PKG_NAME)_INCLUDE_V2ray_Plugin
	bool "Include V2ray-Plugin (Shadowsocks Plugin)"
	select PACKAGE_v2ray-plugin
	default y if aarch64||arm||i386||x86_64

endif
endmenu
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/passwall2
/etc/config/passwall2_server
/usr/share/passwall2/domains_excluded
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
