#!/bin/sh

export PATH=/usr/local/sbin:/usr/local/bin:$PATH

# grapheqd's raw "protocol" (little endian):
# c -> s: 'r'
# s -> c:
#   # of channels (2 bytes)
#   sampling rate (4 bytes)
#   ...pcm data...

MYNAME=`basename "$0"`
SOUNDCARD="$1"
STDERR="$2"

sendpcm () {
  cmd=`dd bs=1 count=1 status=none`
  [ -z "$cmd" ] && exit
  if [ "$cmd" != "r" ]; then
    logmsg "Unsupported command: $cmd"
    exit
  fi

  mixersettings=`mixer -o`
  mixer pcm2.recsrc=set >/dev/null

  rate=""
  channels=""
  ac="2"
  probe=`ffprobe -hide_banner "$SOUNDCARD" 2>&1`
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
    ffmpeg -nostdin -abort_on empty_output -loglevel quiet -i "$SOUNDCARD" \
           -ac "$ac" -c:a pcm_s16le -f s16le -
  else
    logmsg "Unsupported rate and/or channels: $probe"
  fi

  mixer $mixersettings >/dev/null
}

if [ -n "$STDERR" -a "$STDERR" = "stderr" ]; then
  logmsg () {
    echo "${MYNAME}[$$]: $@" >&2
  }

  sendpcm
else
  logmsg () {
    logger -i -p daemon.info -t "$MYNAME" "$@" >/dev/null
  }

  sendpcm 2>/dev/null
fi
