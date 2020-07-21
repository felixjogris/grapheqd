CC ?= cc
KISSFFT ?= ../kissfft

ifdef USE_SYSTEMD
  CFLAGS += -DUSE_SYSTEMD
endif
ifdef BUILD_ROOT
  CFLAGS += -I$(BUILD_ROOT)/usr/include -L$(BUILD_ROOT)/usr/lib
endif

.PHONY:	clean install package

grapheqd:	grapheqd.c rootpage.h favicon.h \
		$(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c
	$(CC) $(CFLAGS) -W -Wall -O3 -s -pipe -I$(KISSFFT) \
        -o $@ grapheqd.c $(KISSFFT)/kiss_fft.c \
        -lasound -lcrypto -lm -lpthread

rootpage.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html "text/html; charset=utf8" rootpage

favicon.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico "image/x-icon" favicon

$(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c: ;	git clone https://github.com/mborgerding/kissfft.git $(KISSFFT)

install:	grapheqd grapheqd.service grapheqd.openrc
	install -d /usr/local/sbin
	install grapheqd /usr/local/sbin/
	install -m 0644 grapheqd.service /lib/systemd/system/ || install grapheqd.openrc /etc/init.d/grapheqd

package:	clean
	$(eval VERSION=$(shell awk -F'"' '{if(/define\s+GRAPHEQD_VERSION/){print $$2}}' grapheqd.c))
	$(eval TMPDIR=$(shell mktemp -d))
	mkdir $(TMPDIR)/grapheqd-$(VERSION)
	cp -aiv * $(TMPDIR)/grapheqd-$(VERSION)/
	tar -C $(TMPDIR) -cvjf $(TMPDIR)/grapheqd-$(VERSION).tar.bz2 grapheqd-$(VERSION)
	sed -i 's/PKG_VERSION:=.*/PKG_VERSION:=$(VERSION)/; '\
	's/PKG_SOURCE:=.*/PKG_SOURCE:=grapheqd-$(VERSION).tar.bz2/; '\
	's/PKG_HASH:=.*/PKG_HASH:='\
	`sha256sum $(TMPDIR)/grapheqd-$(VERSION).tar.bz2 | awk '{print $$1}'`\
	'/' openwrt/Makefile
	sha256sum $(TMPDIR)/grapheqd-$(VERSION).tar.bz2

clean: ;	-rm -v grapheqd
