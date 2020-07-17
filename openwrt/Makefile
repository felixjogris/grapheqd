include $(TOPDIR)/rules.mk

PKG_NAME:=grapheqd
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/grapheqd-${PKG_VERSION}
PKG_SOURCE:=grapheqd-1.tar.bz2
PKG_SOURCE_URL:=https://ogris.de/grapheqd/
PKG_HASH:=0860432a6ab8304d0c56cb4ad925d2949e8d4d2a10574ed773f670d45ac8c010
PKG_BUILD_DEPENDS:=alsa-lib openssl

include $(INCLUDE_DIR)/package.mk

define Package/grapheqd
  SECTION:=sound
  CATEGORY:=Multimedia
  TITLE:=Graphical equalizer daemon
  URL:=https://ogris.de/grapheqd/
  DEPENDS:=+alsa-lib +libopenssl
endef

define Package/grapheqd/description
  grapheqd displays the frequency spectrum of an audio signal via its
  HTML5 webpage or ASCII based telnet interface.
endef

define Package/grapheqd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/hotplug.d/usb
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/grapheqd $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/99-grapheqd $(1)/etc/hotplug.d/usb/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openwrt/grapheqd $(1)/etc/init.d/
endef

$(eval $(call BuildPackage,grapheqd))
