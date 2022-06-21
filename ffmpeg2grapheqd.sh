#!/bin/sh

export PATH=/usr/local/bin:$PATH

# grapheqd's raw "protocol" (little endian):
# c -> s: 'r'
# s -> c:
#   # of channels (2 bytes)
#   sampling rate (4 bytes)
#   ...pcm data...

cmd=`dd bs=1 count=1 status=none 2>&1`
if [ "$cmd" != "r" ]; then
  logger -i -p daemon.info -t "$0" "Unsupported command: $cmd"
  exit
fi

mixersettings=`mixer -s 2>/dev/null`
mixer =rec pcm2 >/dev/null 2>&1

rate=""
channels=""
ac="2"
probe=`ffprobe -hide_banner /dev/dsp0 2>&1`
echo "$probe" | grep -q "44100 Hz" && rate='\104\254\0\0'
echo "$probe" | grep -q "48000 Hz" && rate='\200\273\0\0'
echo "$probe" | grep -q "mono"     && ac="1"
if [ "$ac" = "1" ]; then
  channels='\1\0'
elif [ "$ac" = "2" ]; then
  channels='\2\0'
fi
if [ -n "$rate" -a -n "$ac" -a -n "$channels" ]; then
  printf "${channels}${rate}"
  ffmpeg -nostdin -abort_on empty_output -loglevel quiet -i /dev/dsp0 \
         -ac "$ac" -c:a pcm_s16le -f s16le - 2>/dev/null
else
  logger -i -p daemon.info -t "$0" "Unsupported rate and/or channels: $probe"
fi

mixer $mixersettings >/dev/null 2>&1
