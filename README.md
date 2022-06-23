# grapheqd

grapheqd stands for graphical equalizer daemon. It displays the frequency spectrum of an audio signal via its HTML5 webpage or ASCII based telnet interface. grapheqd runs as a daemon on either Linux with [OpenWRT](https://openwrt.org/) in mind, or FreeBSD. Thus, it uses either ALSA or OSS, choosen at compile time. As FFT computation might require a lot CPU resources on systems without mathematical coprocessor, grapheqd can operate in a client/server mode, where a remote instance on a more powerful system does not use an actual sound device, but connects to a grapheqd instance running on a system with limited CPU power. In such scenarios, you should point your web browser or telnet client only to the remote instance. grapheqd supports PCM signals with one or two channels (read: mono or stereo) and 16 bits per channel. Your audio device must be capable of sampling at 44100 or 48000 Hz. You need a modern web browser with support for JavaScript, CSS3, and websockets in order to access the web interface.

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
graphedq version 3
PCM driver: OSS

Usage:
grapheqd [-a <address>] [-c <address>] [-d] [-l <port>] [-p <pid file>]
         [-r <port>] [-s <soundcard>] [-u <user>]
grapheqd -h

  -a <address>      listen on this address; default: 0.0.0.0
  -c <address>      connect to another grapheqd running at this address, do
                    not use any actual audio hardware; cannot be used in
                    conjunction with option -s
  -d                run in foreground, and log to stdout/stderr, do not detach
                    detach from terminal, do not log to syslog
  -l <port>         listen on this port; default: 8083
  -p <pid file>     daemonize and save pid to this file; no default, pid gets
                    not written to any file
  -r <port>         connect to a remote grapheqd on this port; default: 8083
  -s <soundcard>    read PCM from this soundcard; default: /dev/dsp0; cannot
                    be used in conjunction with either option -c or -r
  -u <user>         switch to this user; no default, run as invoking user
  -h                show this help ;-)

```

## Installation

### Requirements

* KISS FFT by Mark Borgerding to convert PCM data from time to frequency domain

  By default, the grapheqd build process expects a copy of KISS FFT in the directory ../kissfft. You can specify another directory by passing *KISSFFT=/some/other/directory* to *make*. To fetch a copy of KISS FFT, issue this from within the grapheqd directory:

  `git clone https://github.com/mborgerding/kissfft.git ../kissfft`

* On Linux: ALSA library and headers to access your audio device and to read PCM data

  Your Linux distro should have these.

* On FreeBSD: OSS library and headers to access your audio device and to read PCM data

  FreeBSD 4 and newer should have these. However, I just tested with FreeBSD 12.

* OpenSSL crypto library and headers for SHA1 hashing of the *Sec-WebSocket-Accept* header when switching protocols

  Your Linux distro should have these as well.

* (G)libc system library and headers with support for libm for mathematical routines and pthreads for threads, mutexes, and conditions. Any other libc might do as well, but has not been tested yet.

* C compiler. I tested with GCC version 10.1.0, and Clang/LLVM 8.0.1 and 10.0.0.

  For cross compiling you can pass *CC* to *make*, e.g. `make CC=mips-openwrt-linux-gcc`

* On Linux: GNU make or any other compatible make.

* On FreeBSD: default /usr/bin/make or any other compatible make.

### Build

1. Either clone this repository:

   `git clone https://github.com/felixjogris/grapheqd.git`

   or grab an official release from https://ogris.de/grapheqd/

2. If you haven't fetched KISS FFT yet, do it now:

   `git clone https://github.com/mborgerding/kissfft.git ../kissfft`

3. Call `make`. It will use Makefile or GNUmakefile on FreeBSD or Linux, respectively, and fetch KISS FFT automatically if you haven't done it, and will compile everything.

4. Optionally, if you want systemd integration, call *make* with *USE_SYSTEMD=1*

5. You now have *grapheqd* in the current directory. Either call it directly, copy it somewhere, or run `sudo make install`, which will place it to */usr/local/sbin*. Then either add it to your RC init or systemd configuration, or use the provided scripts `grapheqd.service`, `grapheqd.openrc`, or `grapheqd.sh`, which `make install` has copied to `/lib/systemd/system`, `/etc/init.d`, or `/usr/local/etc/rc.d`, respectively.

### OpenWRT

Create a directory *package/grapheqd* inside your copy of the OpenWRT source tree, and download https://ogris.de/grapheqd/openwrt/Makefile to that directory. Now run `make menuconfig`, and under *Multimedia* select *grapheqd*. Optionally, select *kmod-usb-audio* under *Kernel modules* -> *Sound Support*. Then build OpenWRT as usual, e.g. by calling `make`.

[openwrt/Makefile](openwrt/Makefile) is a copy of that Makefile.

## Audio sources

* By default, grapheqd reads PCM data from a soundcard found on the local system. On Linux, ALSA device *hw:0* is used if not overridden by commandline option `-s`. On FreeBSD, the default soundcard is */dev/dsp0*.

* You can also connect to another instance of grapheqd running on a remote host:

  `grapheqd -c <remote host>`

* Starting with version 5, grapheqd can start an external program via commandline option `-e` and read PCM data from the standard output of that program. See ffmpeg2grapheqd.sh for further details.

* You can also place [ffmpeg2grapheqd.sh](ffmpeg2grapheqd.sh) (or any similiar program) on a remote host and make it accessible via inetd, e.g. on FreeBSD:

  1. Place ffmpeg2grapheqd.sh to /usr/local/libexec, which `make install` does by default.

  2. Add this to /etc/inetd.conf:

     `mmcc	stream	tcp	nowait	root	/usr/local/libexec/ffmpeg2grapheqd.sh	ffmpeg2grapheqd.sh`

  3. (Re-)start inetd:

     `service inetd restart`

  4. Start grapheqd with `-c <remote host> -r mmcc`

  If grapheqd runs as user who is not allowed to access local devices or is otherwise prohibited from running the external program, you can also connect to a local instance of inetd if it has been configured as shown in aboves inetd.conf snippet. Simply connect to localhost:

  `grapheqd -c localhost -r mmcc`

## Under the hood

Per channel, grapheqd passes 4096 16 bit audio samples (mono or stereo) at a time to FFT, and pushes calculated linear frequency data to all connected clients, thus resulting in roughly 11 or 12 updates per second if your hardware supports sampling at 44100 or 48000 Hz, respectively. The web interface adjusts the labels under each band (vertical bar) to match its frequency range. If only mono audio is available, then the FFT is called just once per loop, while the output data is duplicated. If no client is connected, then no PCM data is read and FFT does not burn CPU cycles unnecessarily.

The internal web serving routines (to put it nicely) use static and predetermined buffers where possible. printf() and family are not used in the hot code paths and loops.

## Homepage

https://ogris.de/grapheqd/
