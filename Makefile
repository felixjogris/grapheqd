CC ?= cc
KISSFFT ?= ../kissfft
USE_OSS ?= -DUSE_OSS
USE_A52 ?= -DUSE_A52 -la52

.PHONY:	clean install

grapheqd:	grapheqd.c rootpage.h favicon.h \
		$(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c
	$(CC) $(USE_OSS) $(USE_A52) -W -Wall -O3 -s -pipe -I$(KISSFFT) \
        -o $@ grapheqd.c $(KISSFFT)/kiss_fft.c \
        -lm -lpthread -lcrypto

rootpage.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html "text/html; charset=utf8" rootpage

favicon.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico "image/x-icon" favicon

$(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c: ;	git clone https://github.com/mborgerding/kissfft.git $(KISSFFT)

install:	grapheqd grapheqd.sh
	install -d /usr/local/sbin /usr/local/etc/rc.d
	install grapheqd /usr/local/sbin/
	install grapheqd.sh /usr/local/etc/rc.d/grapheqd
	-echo "Don't forget to enable grapheqd, e.g. by 'sysrc grapheqd_enable=YES'"

clean: ;	-rm -v grapheqd
