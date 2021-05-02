#!/bin/sh

export PATH=/usr/local/bin:$PATH

# grapheqd's pcm "protocol" (little endian):
# # of channels (2 bytes)
# sampling rate (4 bytes)

mixersettings=`mixer -s 2>/dev/null`
mixer =rec pcm2 >/dev/null 2>&1

ffprobe -hide_banner /dev/dsp0 2>&1 | grep -q "48000 Hz" && \
  printf '\2\0\200\273\0\0' || printf '\2\0\104\254\0\0'

ffmpeg -loglevel quiet -i /dev/dsp0 -ac 2 -c:a pcm_s16le -f s16le - 2>/dev/null

mixer $mixersettings >/dev/null 2>&1
