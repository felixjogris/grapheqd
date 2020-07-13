#define _GNU_SOURCE
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
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <alsa/asoundlib.h>
#include "kiss_fft.h"
#ifdef USE_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif

#define GRAPHEQD_VERSION "1"

#define SAMPLING_RATE 44100 // Hz
#define SAMPLING_CHANNELS 2 // stereo
#define SAMPLING_WIDTH 2    // 16 bit signed per channel per sample
#define SAMPLING_FORMAT SND_PCM_FORMAT_S16 // keep in sync to SAMPLING_WIDTH
#define FFT_SIZE 2048

#define log_error(fmt, params ...) do { \
  if (foreground) warnx(fmt "\n", ## params); \
  syslog(LOG_ERR, "%s (%s:%i): " fmt "\n", \
         __FUNCTION__, __FILE__, __LINE__, ## params); \
} while (0)

/* integer to string by preprocessor */
#define XSTR(a) #a
#define STR(a) XSTR(a)

/* passed to a client worker thread after accept() */
struct client_worker_arg {
  struct sockaddr addr;
  socklen_t addr_len;
  char clientname[INET6_ADDRSTRLEN + 8];
  int socket;
};

/* used by pcm & fft worker threads */
int pcm_buf_idx = 0;
int16_t pcm_buf[2][FFT_SIZE];
/* used by fft & every client worker thread */
int display_idx = 0;
char display_buf[2][27];
/* used by pcm & every client worker thread */
int num_clients = 0;

/* used by main() and sigterm_handler() */
int running = 1;
/* used by main() and log_error() macro */
int foreground = 0;

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
  if (initgroups(pw->pw_name, pw->pw_gid))
    err(1, "initgroups()");
  if (setgid(pw->pw_gid))
    err(1, "setgid()");
  if (setuid(pw->pw_uid))
    err(1, "setuid()");
}

static snd_pcm_t *open_alsa (char *soundcard)
{
  snd_pcm_t *handle;
  snd_pcm_hw_params_t *params;
  int err;

  err = snd_pcm_open(&handle, soundcard, SND_PCM_STREAM_CAPTURE, 0);
  if (err)
    errx(1, "cannot open %s for capturing: %s", soundcard, snd_strerror(err));

  err = snd_pcm_hw_params_malloc(&params);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_alloca()", snd_strerror(err));

  err = snd_pcm_hw_params_any(handle, params);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_any()", snd_strerror(err));

  err = snd_pcm_hw_params_set_access(handle, params,
                                     SND_PCM_ACCESS_RW_INTERLEAVED);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_access(INTERLEAVED)",
                      snd_strerror(err));

  err = snd_pcm_hw_params_set_format(handle, params, SAMPLING_FORMAT);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_format("
                      STR(SAMPLING_WIDTH*2) ")", snd_strerror(err));

  err = snd_pcm_hw_params_set_channels(handle, params, SAMPLING_CHANNELS);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_channels("
                      STR(SAMPLING_CHANNELS) ")", snd_strerror(err));

  err = snd_pcm_hw_params_set_rate(handle, params, SAMPLING_RATE, 0);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_rate(" STR(SAMPLING_RATE) ")",
                      snd_strerror(err));

  err = snd_pcm_hw_params_set_period_size(handle, params, FFT_SIZE, 0);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_period_size(" STR(FFT_SIZE) ")",
                      snd_strerror(err));

  err = snd_pcm_hw_params(handle, params);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params()", snd_strerror(err));

  snd_pcm_hw_params_free(params);

  return handle;
}

static int wait_for_client (int listen_socket)
{
  int res;
  fd_set rfds;

  FD_ZERO(&rfds);
  FD_SET(listen_socket, &rfds);

  res = select(listen_socket + 1, &rfds, NULL, NULL, NULL);

  if (res < 0) {
    if (errno == EINTR) {
      res = 0;
    } else {
      log_error("select(): %s", strerror(errno));
    }
  }

  return res;
}

static void client_address (struct client_worker_arg *arg)
{
  char addr[INET6_ADDRSTRLEN];
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  switch (arg->addr.sa_family) {
    case AF_INET:
      sin = (struct sockaddr_in*) &arg->addr;
      snprintf(arg->clientname, sizeof(arg->clientname), "%s:%u",
               inet_ntop(sin->sin_family, &sin->sin_addr, addr, sizeof(addr)),
               htons(sin->sin_port));
      break;
    case AF_INET6:
      sin6 = (struct sockaddr_in6*) &arg->addr;
      snprintf(arg->clientname, sizeof(arg->clientname), "[%s]:%u",
               inet_ntop(sin6->sin6_family, &sin6->sin6_addr, addr,
                         sizeof(addr)),
               htons(sin6->sin6_port));
      break;
    default:
      snprintf(arg->clientname, sizeof(arg->clientname),
               "<unknown address family %u>", arg->addr.sa_family);
      break;
  }
}

static void * client_worker (void *arg0)
{
  struct client_worker_arg *arg = arg0;

  pthread_setname_np(pthread_self(), "grapheqd:client");
  client_address(arg);

  return NULL;
}

static int create_client_worker (int listen_socket)
{
  pthread_t thread;
  struct client_worker_arg *arg;
  int res;

  arg = malloc(sizeof(*arg));
  if (arg == NULL) {
    log_error("malloc(): out of memory");
    return ENOMEM;
  }

  do {
    arg->addr_len = sizeof(arg->addr);
    arg->socket = accept(listen_socket, &arg->addr, &arg->addr_len);
  } while ((arg->socket < 0) && (errno == EINTR));

  if (arg->socket < 0) {
    log_error("accept(): %s", strerror(errno));
    free(arg);
    return 0;
  }

  res = pthread_create(&thread, NULL, &client_worker, arg);
  if (res != 0)
    log_error("cannot create client worker thread: %s", strerror(res));

  return res;
}

static void * pcm_worker (void *arg0)
{
  snd_pcm_t *soundhandle = (snd_pcm_t*) arg0;

  pthread_setname_np(pthread_self(), "grapheqd:pcm");

  return NULL;
}

static void * fft_worker (void *arg0)
{
  kiss_fft_cfg fft_cfg = (kiss_fft_cfg) arg0;

  pthread_setname_np(pthread_self(), "grapheqd:fft");

  return NULL;
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
  int res, listen_socket;
  char *address = "0.0.0.0", *port = "8083", *pidfile = NULL,
       *soundcard = "hw:0";
  struct passwd *user = NULL;
  snd_pcm_t *soundhandle;
  kiss_fft_cfg fft_cfg;
  pthread_t thread;

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

  fft_cfg = kiss_fft_alloc(FFT_SIZE, 0, NULL, NULL);
  if (!fft_cfg)
    errx(1, "cannot initialize FFT state");

  res = pthread_create(&thread, NULL, &pcm_worker, soundhandle);
  if (res != 0)
    errx(1, "cannot create pcm worker thread: %s", strerror(res));

  res = pthread_create(&thread, NULL, &fft_worker, fft_cfg);
  if (res != 0)
    errx(1, "cannot create fft worker thread: %s", strerror(res));

  setup_signals();

  if (!foreground) {
    close(0); close(1); close(2);
  }

  openlog("grapheqd", LOG_NDELAY|LOG_PID, LOG_DAEMON);
  syslog(LOG_INFO, "starting...\n");

#ifdef USE_SYSTEMD
  sd_notify(0, "READY=1");
#endif

  while (running) {
    res = wait_for_client(listen_socket);

    if (res < 0)
      running = 0;
    if (res > 0)
      if (create_client_worker(listen_socket))
        running = 0;
/*
{
puts("moof");
int16_t buf[2*2048];
snd_pcm_sframes_t n=snd_pcm_readi(soundhandle, (void*) buf , 2048);
printf("read %li frames\n", n);
if (n<0) puts(snd_strerror(n));
}
*/
  }

  snd_pcm_close(soundhandle);
  if (pidfile)
    unlink(pidfile); /* may fail, e.g. due to changed user privs */

  syslog(LOG_INFO, "exiting...\n");
  closelog();

  return 0;
}
