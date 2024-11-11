#
# Copyright (C) 2024 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=unetacl
PKG_VERSION:=1

PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=Felix Fietkau <nbd@nbd.name>

PKG_BUILD_DEPENDS:=bpf-headers

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/unetacl
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Network filter for client access control
  DEPENDS:=+ucode \
	+ucode-mod-bpf +ucode-mod-struct +ucode-mod-rtnl +ucode-mod-socket \
	+ucode-mod-uloop +ucode-mod-ubus +ucode-mod-nl80211 \
	+kmod-ifb +kmod-sched-core +kmod-sched-bpf
endef

define Package/unetacl/conffiles
/etc/unetacl/config.json
/etc/unetacl/state.json
endef

TARGET_CFLAGS += \
	-Wno-error=deprecated-declarations \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	-I$(STAGING_DIR)/usr/include -g3

UCODE_SOURCES = ucode.c packet.c dns.c dhcp.c cache.c

define Build/Compile
	$(call CompileBPF,$(PKG_BUILD_DIR)/unetacl-bpf.c)
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) $(FPIC) \
		-Wall -ffunction-sections -Wl,--gc-sections -shared -Wl,--no-as-needed \
		-o $(PKG_BUILD_DIR)/unetacl_utils.so $(patsubst %,$(PKG_BUILD_DIR)/%,$(UCODE_SOURCES)) -lubox
endef

define Package/unetacl/install
	$(INSTALL_DIR) \
		$(1)/lib/bpf \
		$(1)/usr/lib/ucode/unetacl
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/unetacl_utils.so $(1)/usr/lib/ucode/unetacl/utils.so
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/unetacl-bpf.o $(1)/lib/bpf
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,unetacl))
