CC ?= cc
KISSFFT ?= ../kissfft

.PHONY:	clean

grapheqd:	grapheqd.c $(KISSFFT)/kiss_fft.h $(KISSFFT)/kiss_fft.c
	$(CC) -W -Wall -O3 -s -pipe -Dkiss_fft_scalar=float -o $@ grapheqd.c $(KISSFFT)/kiss_fft.c -lm

clean: ;	-rm -v grapheqd
