#!/bin/sh

export PATH=/usr/local/bin:$PATH

# grapheqd's pcm "protocol" (little endian):
# # of channels (2 bytes)
# sampling rate (4 bytes)

mixersettings=`mixer -s 2>/dev/null`
mixer =rec pcm2 >/dev/null 2>&1

rate=""
channels=""
ac=""
probe=`ffprobe -hide_banner /dev/dsp0 2>&1` || exit 1
echo "$probe" | grep -q "44100 Hz" && rate='\104\254\0\0'
echo "$probe" | grep -q "48000 Hz" && rate='\200\273\0\0'
echo "$probe" | grep -q "mono"     && ac="1"
echo "$probe" | grep -q "stereo"   && ac="2"
if [ "$ac" = "1" ]; then
  channels='\1\0'
elif [ "$ac" = "2" ]; then
  channels='\2\0'
fi
if [ -z "$rate" -o -z "$ac" -o -z "$channels" ]; then
  (echo "Unsupported rate and/or channels:"
   echo "$probe") | logger -i -p daemon.info -t "$0"
  exit 1
fi

printf "${channels}${rate}"

ffmpeg -loglevel quiet -i /dev/dsp0 -ac "$ac" -c:a pcm_s16le -f s16le - 2>/dev/null

mixer $mixersettings >/dev/null 2>&1
