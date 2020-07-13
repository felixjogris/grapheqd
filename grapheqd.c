#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/select.h>
#include <syslog.h>
#include <sys/socket.h>
#include <pwd.h>
#include <pthread.h>
#include <alsa/asoundlib.h>
#include "kiss_fft.h"

#define GRAPHEQD_VERSION "1"

int running = 1;

static void sigterm_handler (int sig __attribute__((unused)))
{
  syslog(LOG_INFO, "SIGTERM received, going down...\n");
  running = 0;
}

static void setup_signal (int sig, void (*handler)(int))
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  if (sigaction(sig, &sa, NULL) != 0)
    err(1, "signal()");
}

static void setup_signals ()
{
  sigset_t sigset;

  if (sigfillset(&sigset) != 0)
    err(1, "sigfillset()");

  if (sigdelset(&sigset, SIGTERM) != 0)
    err(1, "sigdelset()");

  if (pthread_sigmask(SIG_SETMASK, &sigset, NULL) != 0)
    err(1, "pthread_sigmask()");

  setup_signal(SIGTERM, sigterm_handler);
}

static struct passwd *get_user (char *username)
{
  struct passwd *pw = getpwnam(username);

  if (!pw)
    errx(1, "no such user: %s", username);

  return pw;
}

static int create_listen_socket_inet (char *ip, char *port)
{
  int listen_socket, yes, res;
  struct addrinfo hints, *result, *walk;

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE | AI_NUMERICSERV;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if ((res = getaddrinfo(ip, port, &hints, &result)) != 0)
    errx(1, "getaddrinfo(): %s", gai_strerror(res));

  for (walk = result;;) {
    listen_socket = socket(walk->ai_family, walk->ai_socktype, 0);
    if ((listen_socket >= 0) &&
        (bind(listen_socket, walk->ai_addr, walk->ai_addrlen) == 0))
      break;

    if (walk->ai_next == NULL)
      err(1, "bind()");

    close(listen_socket);
  }

  freeaddrinfo(result);

  yes = 1;
  res = setsockopt(listen_socket, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
  if (res != 0)
    err(1, "setsockopt(REUSEPORT)");

  yes = 1;
  res = setsockopt(listen_socket, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
  if (res != 0)
    err(1, "setsockopt(KEEPALIVE)");

  if (listen(listen_socket, 0) != 0)
    err(1, "listen()");

  return listen_socket;
}

static void daemonize ()
{
  pid_t pid;

  if ((pid = fork()) < 0)
    err(1, "fork()");

  if (pid > 0)
    exit(0);

  if (setsid() == -1)
    err(1, "setsid()");

  if (chdir("/"))
    err(1, "chdir(/)");
}

static void save_pidfile (char *pidfile)
{
  int fd, len;
  char pid[16];

  fd = open(pidfile, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  if (fd < 0)
    err(1, "cannot open %s for writing", pidfile);

  if (flock(fd, LOCK_EX | LOCK_NB))
    errx(1, "cannot lock %s (grapheqd still running?)", pidfile);

  len = snprintf(pid, sizeof(pid), "%u\n", getpid());

  if (write(fd, pid, len) != len)
    errx(1, "cannot write %s", pidfile);

  if (close(fd))
    errx(1, "cannot close %s", pidfile);
}

static void change_user (struct passwd *pw)
{
  if (initgroups(pw->pw_nam, pw->pw_gid))
    err(1, "initgroups()");
  if (setgid(pw->pw_gid))
    err(1, "setgid()");
  if (setuid(pw->pw_uid))
    err(1, "setuid()");
}

static snd_pcm_t *open_alsa (char *soundcard)
{
  snd_pcm_t *handle;
  snd_pcm_hw_params_t params;
  int err;

  err = snd_pcm_open(&handle, soundcard, SND_PCM_STREAM_CAPTURE, 0);
  if (err)
    errx(1, "cannot open %s for capturing: %s", soundcard, snd_strerror(err));

  err = snd_pcm_hw_params_any(handle, &params);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_any()", snd_strerror(err));

  err = snd_pcm_hw_params_set_format(handle, &params, SND_PCM_FORMAT_S16);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_format(S16)", snd_strerror(err));

  err = snd_pcm_hw_params_set_channels(handle, &params, 2);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_channels(2)", snd_strerror(err));

  err = snd_pcm_hw_params_set_access(handle, &params,
                                     SND_PCM_ACCESS_RW_NONINTERLEAVED);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_access(NONINTERLEAVED)",
                      snd_strerror(err));

  err = snd_pcm_hw_params(handle, &params);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params()", snd_strerror(err));

  return handle;
}

static void show_help ()
{
  puts(
"graphedq version " GRAPHEQD_VERSION "\n"
"\n"
"Usage:\n"
"\n"
"grapheqd [-a <address>] [-d] [-l <port>] [-p <pid file>] [-s <soundcard>]\n"
"         [-u <user>]\n"
"grapheqd -h\n"
"\n"
"  -a <address>        listen on this address; default: 0.0.0.0\n"
"  -d                  run in foreground and do not detach from terminal\n"
"  -l <port>           listen on this port; default: 8083\n"
"  -p <pid file>       daemonize and save pid to this file; no default, pid\n"
"                      gets not written to any file\n"
"  -s <soundcard>      read PCM from this soundcard; default: hw:0\n"
"  -u <user>           switch to this user; no default, run as invoking user\n"
"  -h                  show this help ;-)\n"
);
}

int main (int argc, char **argv)
{
  int res, foreground = 0, listen_socket;
  char *address = "0.0.0.0", *port = "8083", *pidfile = NULL,
       *soundcard = "hw:0";
  struct passwd *user = NULL;
  snd_pcm_t *sndcard;

  while ((res = getopt(argc, argv, "a:dhl:p:s:u:")) != -1) {
    switch (res) {
      case 'a': address = optarg; break;
      case 'd': foreground = 1; break;
      case 'h': show_help(); return 0;
      case 'l': port = optarg; break;
      case 'p': pidfile = optarg; break;
      case 's': soundcard = optarg; break;
      case 'u': user = get_user(optarg); break;
      default: errx(1, "Unknown option '%i'. See -h for help.", res);
    }
  }

  listen_socket = create_listen_socket_inet(address, port);
  soundhandle = open_alsa(soundcard);
  if (!foreground)
    daemonize();
  if (pidfile)
    save_pidfile(pidfile);
  if (user)
    change_user(user);
  setup_signals();
  if (!foreground) {
    close(0); close(1); close(2);
  }

//  while (running) {
  // accept loop
//  }

  /* both may fail, e.g. due to changed user privs */
  snd_pcm_close(soundhandle);
  if (pidfile)
    unlink(pidfile);

  return 0;
}
