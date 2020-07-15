CC ?= cc
KISSFFT ?= ../kissfft

.PHONY:	clean

grapheqd:	grapheqd.c rootpage.h favicon.h $(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c
	$(CC) -W -Wall -O3 -pipe -I$(KISSFFT) -Dkiss_fft_scalar=float -o $@ grapheqd.c $(KISSFFT)/kiss_fft.c -lm -lpthread -lasound

rootpage.h:	rootpage.html bin2c.pl
	perl bin2c.pl rootpage.html "text/html" rootpage

favicon.h:	favicon.ico bin2c.pl
	perl bin2c.pl favicon.ico "image/x-icon" favicon

clean: ;	-rm -v grapheqd
