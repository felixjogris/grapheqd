CC ?= cc
CFLAGS = -W -Wall -O3 -pipe -DUSE_OSS
LDFLAGS = -s
KISSFFT ?= ../kissfft

.PHONY:	clean install

grapheqd:	grapheqd.o $(KISSFFT)/libkissfft-float.a
	$(CC) $(LDFLAGS) -o $@ grapheqd.o -L$(KISSFFT) -lcrypto -lm -lpthread \
		-lkissfft-float

grapheqd.o:	grapheqd.c rootpage.h favicon.h $(KISSFFT)/kiss_fft.h
	$(CC) $(CFLAGS) -I$(KISSFFT) -c -o $@ grapheqd.c

$(KISSFFT)/libkissfft-float.a:	$(KISSFFT)/kiss_fft.h
	gmake -C$(KISSFFT) KISSFFT_TOOLS=0 KISSFFT_STATIC=1

rootpage.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html "text/html; charset=utf8" rootpage

favicon.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico "image/x-icon" favicon

$(KISSFFT)/kiss_fft.h:
	git clone https://github.com/mborgerding/kissfft.git $(KISSFFT)

install:	grapheqd grapheqd.sh ffmpeg2grapheqd.sh
	install -d /usr/local/sbin /usr/local/etc/rc.d
	install grapheqd /usr/local/sbin/
	install grapheqd.sh /usr/local/etc/rc.d/grapheqd
	install ffmpeg2grapheqd.sh /usr/local/libexec/
	-echo "Don't forget to enable grapheqd, e.g. by" \
		"'sysrc grapheqd_enable=YES'"

clean: ;	-rm -v grapheqd *.o
