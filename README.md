# grapheqd

grapheqd stands for graphical equalizer daemon. It displays the frequency spectrum of an audio signal via its HTML5 webpage or ASCII based telnet interface. grapheqd runs as a daemon on Linux with [OpenWRT](https://openwrt.org/) in mind. It supports PCM signals with one or two channels (read: mono or stereo) and 16 bits per channel. Your audio device must be capable of sampling at 44100 or 48000 Hz. You need a modern web browser with support for JavaScript, CSS3, and websockets in order to access the web interface.

## Background

Back in the 80ies and 90ies hifis and stereos came with a graphical equalizer as a separate, physical device, or could be equipped with one. You don't easily find one of these nowadays, at least not for the consumer market. I have never found any use of actually adjusting the audio signal, but always liked the fluorescent dot matrix displays or LCDs. grapheqd tries to reassemble this.

## Screenshots

The web interface runs on port 8083 by default:

![web interface](https://ogris.de/grapheqd/web.png)

Point your telnet client to port 8083 as well, and simply enter a *c* followed by *Enter* to access the ASCII interface in color mode:

![ascii interface in color mode](https://ogris.de/grapheqd/asciicolor.png)

If your terminal does not support colors and/or escape sequences, press *m* followed by *Enter*:

![ascii interface in mono mode](https://ogris.de/grapheqd/asciimono.png)

## Help

```
$ ./grapheqd -h
graphedq version 1

Usage:

grapheqd [-a <address>] [-d] [-l <port>] [-p <pid file>] [-s <soundcard>]
         [-u <user>]
grapheqd -h

  -a <address>        listen on this address; default: 0.0.0.0
  -d                  run in foreground and do not detach from terminal
  -l <port>           listen on this port; default: 8083
  -p <pid file>       daemonize and save pid to this file; no default, pid
                      gets not written to any file
  -s <soundcard>      read PCM from this soundcard; default: hw:0
  -u <user>           switch to this user; no default, run as invoking user
  -h                  show this help ;-)

```

## Installation

### Requirements

* KISS FFT by Mark Borgerding to convert PCM data from time to frequency domain
  By default, the grapheqd build process expects a copy of KISS FFT in the directory ../kissfft. You can specify another directory by passing *KISSFFT=/some/other/directory* to *make*. To fetch a copy of KISS FFT, issue this from within the grapheqd directory:
  `git clone https://github.com/mborgerding/kissfft.git ../kissfft`

* ALSA library and headers to access your audio device and to read PCM data
  Your Linux distro should have these.

* OpenSSL crypto library and headers for SHA1 hashing of the *Sec-WebSocket-Accept* header when switching protocols
  Your Linux distro should have these as well.

* Glibc system library and headers with support for libm for mathematical routines and pthreads for threads, mutexes, and conditions. Any other libc might do as well, but has not been tested yet.

* C compiler. I tested with GCC version 10.1.0 and Clang/LLVM 10.0.0.
  For cross compiling you can pass *CC* to *make*, e.g. `make CC=mips-openwrt-linux-gcc`

* GNU make or any other compatible make.

### Build

1. For now, clone this repository:

   `git clone https://github.com/felixjogris/grapheqd.git`

2. If you haven't fetched KISS FFT yet, do it now:

   `git clone https://github.com/mborgerding/kissfft.git ../kissfft`

3. Call `make`.

4. Optionally, if you want systemd integration, call *make* with *USE_SYSTEMD=1*

5. You now have *grapheqd* in the current directory. Either call it directly, or copy it to */usr/local/bin* and add it to your RC init or systemd configuration.

I am putting an official release as .tar.bz2 with proper RC scripts to https://ogris.de/grapheqd/ as soon as I finish OpenWRT integration.

## Under the hood

Per channel, grapheqd passes 4096 16 bit audio samples (mono or stereo) at a time to FFT, and pushes calculated linear frequency data to all connected clients, thus resulting in roughly 11 or 12 updates per second if your hardware supports sampling at 44100 or 48000 Hz, respectively. The web interface adjusts the labels under each band (vertical bar) to match its frequency range. If only mono audio is available, then the FFT is called just once per loop, while the output data is duplicated. If no client is connected, then no PCM data is read and FFT does not burn CPU cycles unnecessarily. The internal web serving routines (to put it nicely) use static and predetermined buffers where possible. printf() and family are not used in the hot code paths and loops.
