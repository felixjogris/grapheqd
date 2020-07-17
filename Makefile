CC ?= cc
KISSFFT ?= ../kissfft

ifdef USE_SYSTEMD
  CFLAGS += -DUSE_SYSTEMD
endif
ifdef BUILD_ROOT
  CFLAGS += -I$(BUILD_ROOT)/usr/include -L$(BUILD_ROOT)/usr/lib
endif

.PHONY:	clean install foo

grapheqd:	grapheqd.c rootpage.h favicon.h \
                $(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c
	$(CC) $(CFLAGS) -W -Wall -O3 -s -pipe \
        -I$(KISSFFT) -Dkiss_fft_scalar=float \
        -o $@ grapheqd.c $(KISSFFT)/kiss_fft.c \
        -lm -lpthread -lasound -lcrypto

rootpage.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html "text/html; charset=utf8" rootpage

favicon.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico "image/x-icon" favicon

$(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c: ;	git clone https://github.com/mborgerding/kissfft.git $(KISSFFT)

install:	grapheqd
	install -d /usr/local/sbin
	install grapheqd /usr/local/sbin/
	install -m 0644 grapheqd.service /lib/systemd/system/ || install -m 0644 grapheqd.openrc /etc/init.d/

clean: ;	-rm -v grapheqd
