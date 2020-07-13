CC ?= cc
KISSFFT ?= ../kissfft

.PHONY:	clean

grapheqd:	grapheqd.c $(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c
	$(CC) -W -Wall -O3 -s -pipe -I$(KISSFFT) -Dkiss_fft_scalar=float -o $@ grapheqd.c $(KISSFFT)/kiss_fft.c -lm -lpthread -lasound

clean: ;	-rm -v grapheqd
