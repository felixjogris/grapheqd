#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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
#define SAMPLING_FORMAT SND_PCM_FORMAT_S16 /* keep in sync to SAMPLING_WIDTH
                                              and every use of int16_t */
#define DISPLAY_BANDS 27 /* 27 bands/buckets per channel displayed */
#define DISPLAY_BARS 25  /* 25 segments per band */
#define FFT_SIZE 4096    /* must be power of 2 */

#define log_error(fmt, params ...) do { \
  if (foreground) warnx(fmt "\n", ## params); \
  syslog(LOG_ERR, "%s (%s:%i): " fmt "\n", \
         __FUNCTION__, __FILE__, __LINE__, ## params); \
} while (0)

#define log_info(fmt, params ...) do { \
  if (foreground) printf(fmt "\n", ## params); \
  syslog(LOG_INFO, fmt "\n", ## params); \
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

static int pcm_idx = 0;
static int16_t pcm_buf[2][FFT_SIZE * SAMPLING_CHANNELS];
static pthread_mutex_t pcm_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pcm_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t fft_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fft_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t display_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t display_cond = PTHREAD_COND_INITIALIZER;
static int display_idx = 0;
static unsigned char display_buf[2][SAMPLING_CHANNELS][DISPLAY_BANDS];
static int num_clients = 0;
static pthread_mutex_t num_mtx = PTHREAD_MUTEX_INITIALIZER;

/* used by main() and sigterm_handler() */
static int running = 1;
/* used by main() and log_error() macro */
static int foreground = 0;

static void sigterm_handler (int sig __attribute__((unused)))
{
  log_info("SIGTERM received, going down...");
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

static struct passwd *get_user (const char *username)
{
  struct passwd *pw = getpwnam(username);

  if (!pw)
    errx(1, "no such user: %s", username);

  return pw;
}

static int create_listen_socket_inet (const char *ip, const char *port)
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
    if (listen_socket < 0)
      continue;

    yes = 1;
    res = setsockopt(listen_socket, SOL_SOCKET, SO_REUSEPORT, &yes,
                     sizeof(yes));
    if (res != 0) {
      close(listen_socket);
      continue;
    }

    yes = 1;
    res = setsockopt(listen_socket, SOL_SOCKET, SO_KEEPALIVE, &yes,
                     sizeof(yes));
    if (res != 0) {
      close(listen_socket);
      continue;
    }

    if (bind(listen_socket, walk->ai_addr, walk->ai_addrlen) == 0)
      break;

    walk = walk->ai_next;
    if (!walk)
      err(1, "bind()");

    close(listen_socket);
  }

  freeaddrinfo(result);

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

static void save_pidfile (const char *pidfile)
{
  int fd, len;
  char pid[16];

  fd = open(pidfile, O_CREAT | O_WRONLY | O_TRUNC | O_EXCL | O_NOFOLLOW,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd < 0)
    err(1, "cannot create %s for writing (if grapheqd is not running, "
           "please remove stale pidfile)", pidfile);

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

static snd_pcm_t *open_alsa (const char *soundcard)
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

/* FIXME */
  err = snd_pcm_hw_params_set_channels(handle, params, SAMPLING_CHANNELS);
  if (err)
warnx("%s: %s", "snd_pcm_hw_params_set_channels("
                      STR(SAMPLING_CHANNELS) ")", snd_strerror(err));

/* FIXME */
  err = snd_pcm_hw_params_set_rate(handle, params, SAMPLING_RATE, 0);
  if (err)
warnx( "%s: %s", "snd_pcm_hw_params_set_rate(" STR(SAMPLING_RATE) ")",
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

static char fill_band (float (*level)[FFT_SIZE / 2], float max_level,
                       int start, int end)
{
  float sum = 0.;
  int i;

  for (i = start; i < end; i++)
    sum += (*level)[i];

  return floor((DISPLAY_BARS * sum) / ((end - start) * max_level));
}

static void fill_bands (float (*level)[FFT_SIZE / 2], float max_level,
                        unsigned char (*display)[DISPLAY_BANDS])
{
  /* base values for 2048 fft size at 44100 Hz */
  const int c = FFT_SIZE / 2048;

#if SAMPLING_RATE==44100
  /* 21.5 Hz */
  (*display)[0] = fill_band(level, max_level,  c*0,  c*1);
  /* 43 */
  (*display)[1] = fill_band(level, max_level,  c*1,  c*2);
  /* 64.5 */
  (*display)[2] = fill_band(level, max_level,  c*2,  c*3);
  /* 86 */
  (*display)[3] = fill_band(level, max_level,  c*3,  c*4);
  /* 107.5 */
  (*display)[4] = fill_band(level, max_level,  c*4,  c*5);
  /* 129 - 150.5 */
  (*display)[5] = fill_band(level, max_level,  c*5,  c*7);
  /* 172 - 193.5 */
  (*display)[6] = fill_band(level, max_level,  c*7,  c*9);
  /* 215 - 236.5 */
  (*display)[7] = fill_band(level, max_level,  c*9,  c*11);
  /* 258 - 301 */
  (*display)[8] = fill_band(level, max_level,  c*11, c*14);
  /* 322.5 - 387 */
  (*display)[9] = fill_band(level, max_level,  c*15, c*18);
  /* 408.5 - 494.5 */
  (*display)[10] = fill_band(level, max_level, c*18, c*23);
  /* 473 - 602 */
  (*display)[11] = fill_band(level, max_level, c*23, c*28);
  /* 623.5 - 795.5*/
  (*display)[12] = fill_band(level, max_level, c*28, c*37);
  /* 817 - 989 */
  (*display)[13] = fill_band(level, max_level, c*37, c*46);
  /* 1010.5 - 1225.5 */
  (*display)[14] = fill_band(level, max_level, c*46, c*57);
  /* 1247 - 1483.5 */
  (*display)[15] = fill_band(level, max_level, c*57, c*69);
  /* 1505 - 1978 */
  (*display)[16] = fill_band(level, max_level, c*69, c*92);
  /* 1999.5 - 2472.5 */
  (*display)[17] = fill_band(level, max_level, c*92, c*115);
  /* 2494 - 3182 */
  (*display)[18] = fill_band(level, max_level, c*115, c*148);
  /* 3203.5 - 3891.5 */
  (*display)[19] = fill_band(level, max_level, c*148, c*181);
  /* 3913 - 5075 */
  (*display)[20] = fill_band(level, max_level, c*181, c*236);
  /* 5095.5 - 6278 */
  (*display)[21] = fill_band(level, max_level, c*236, c*292);
  /* 6299.5 - 8127 */
  (*display)[22] = fill_band(level, max_level, c*292, c*378);
  /* 8148.5 - 9976 */
  (*display)[23] = fill_band(level, max_level, c*378, c*464);
  /* 9997.5 - 12986 */
  (*display)[24] = fill_band(level, max_level, c*464, c*604);
  /* 13007.5 - 15996 */
  (*display)[25] = fill_band(level, max_level, c*604, c*744);
  /* 16017.5 - 22050 */
  (*display)[26] = fill_band(level, max_level, c*744, c*1024);
#elif SAMPLING_RATE==48000
#else
#  error Unknown SAMPLING_RATE
#endif
}

static float calculate_power (kiss_fft_cpx fft_out, float *max_level)
{
  float power = sqrt(fft_out.r * fft_out.r + fft_out.i * fft_out.i);

  if (power > *max_level) {
    *max_level = power;
    log_info("max_level=%f", *max_level);
  }

  return power;
}

static void *fft_worker (void *arg0)
{
  kiss_fft_cfg fft_cfg = (kiss_fft_cfg) arg0;
  int res, i, new_pcm_idx;
  kiss_fft_cpx lin[FFT_SIZE], rin[FFT_SIZE];
  kiss_fft_cpx lout[FFT_SIZE], rout[FFT_SIZE];
  float llevel[FFT_SIZE / 2], rlevel[FFT_SIZE / 2];
  /* kiss_fft emits 131072 when fed with a pure sine, so it's a good starting
     point */
  static float max_level = 131072.;

  pthread_setname_np(pthread_self(), "grapheqd:fft");

  res = pthread_mutex_lock(&fft_mtx);
  if (res) {
    log_error("cannot lock fft mutex: %s", strerror(res));
    return NULL;
  }

  while (running) {
    /* wait for pcm thread to wake us up */
    res = pthread_cond_wait(&fft_cond, &fft_mtx);
    if (res) {
      log_error("cannot wait for fft condition: %s", strerror(res));
      break;
    }

    new_pcm_idx = pcm_idx;
    new_pcm_idx = 1 - new_pcm_idx;

    for (i = 0; i < FFT_SIZE; i++) {
      /* left channel */
      lin[i].r = pcm_buf[new_pcm_idx][2 * i];
      lin[i].i = 0;
      /* right channel */
      rin[i].r = pcm_buf[new_pcm_idx][2 * i + 1];
      rin[i].i = 0;
    }

    kiss_fft(fft_cfg, &lin[0], &lout[0]);
    kiss_fft(fft_cfg, &rin[0], &rout[0]);

    for (i = 0; i < FFT_SIZE / 2; i++) {
      llevel[i] = calculate_power(lout[i], &max_level);
      rlevel[i] = calculate_power(rout[i], &max_level);
    }

    fill_bands(&llevel, max_level, &display_buf[display_idx][0]);
    fill_bands(&rlevel, max_level, &display_buf[display_idx][1]);

    display_idx = 1 - display_idx;

    /* wake up all client threads */
    res = pthread_cond_broadcast(&display_cond);
    if (res) {
      log_error("cannot signal display condition: %s", strerror(res));
      break;
    }
  }

  res = pthread_mutex_unlock(&fft_mtx);
  if (res)
    log_error("cannot unlock fft mutex: %s", strerror(res));

  return NULL;
}

static int pcm_worker_loop (snd_pcm_t *soundhandle)
{
  int res;
  snd_pcm_sframes_t num_frames;

  while (num_clients > 0) {
    num_frames = snd_pcm_readi(soundhandle, &pcm_buf[pcm_idx], FFT_SIZE);

    if (num_frames < 0) {
      /* retry */
      snd_pcm_prepare(soundhandle);
      num_frames = snd_pcm_readi(soundhandle, &pcm_buf[pcm_idx], FFT_SIZE);
    }

    if (num_frames < 0) {
      log_error("cannot read pcm data: %s", snd_strerror(num_frames));
      return -1;
    }

    if (num_frames != FFT_SIZE) {
      log_error("read %li bytes of pcm data instead of %i", num_frames,
                FFT_SIZE);
    }

    pcm_idx = 1 - pcm_idx;

    /* wake up fft thread */
    res = pthread_cond_signal(&fft_cond);
    if (res) {
      log_error("cannot signal fft condition: %s", strerror(res));
      return -1;
    }
  }

  return 0;
}

static void *pcm_worker (void *arg0)
{
  snd_pcm_t *soundhandle = (snd_pcm_t*) arg0;
  int res;

  pthread_setname_np(pthread_self(), "grapheqd:pcm");

  res = pthread_mutex_lock(&pcm_mtx);
  if (res) {
    log_error("cannot lock pcm mutex: %s", strerror(res));
    return NULL;
  }

  while (running) {
    /* wait for a client thread to wake us up */
    res = pthread_cond_wait(&pcm_cond, &pcm_mtx);
    if (res) {
      log_error("cannot wait for pcm condition: %s", strerror(res));
      break;
    }

    if (pcm_worker_loop(soundhandle))
      break;
  }

  res = pthread_mutex_unlock(&pcm_mtx);
  if (res)
    log_error("cannot unlock pcm mutex: %s", strerror(res));

  return NULL;
}

static int count_client (int i)
{
  int res;

  res = pthread_mutex_lock(&num_mtx);
  if (res) {
    log_error("cannot lock num_clients mutex: %s", strerror(res));
    return res;
  }

  num_clients += i;

  res = pthread_mutex_unlock(&num_mtx);
  if (res)
    log_error("cannot unlock num_clients mutex: %s", strerror(res));

  return res;
}

static int json_display (int new_display_idx, char buf[32768])
{
// TODO
  return 0;
}

static void set_color (char c, char intens, char *p)
{
  *p++ = 27;
  *p++ = '[';
  *p++ = intens;
  *p++ = ';';
  *p++ = '3';
  *p++ = '6';
  *p++ = ';';
  *p++ = '4';
  *p++ = '0';
  *p++ = 'm';
  *p++ = c;
  *p++ = 27;
  *p++ = '[';
  *p++ = '0';
  *p++ = 'm';
}

static int color_display (int new_display_idx, char buf[21504])
{
  int row, col, idx = 0;

  for (row = DISPLAY_BARS; row > 0; row--) {
    buf[idx++] = '\n';

    for (col = 0; col < DISPLAY_BANDS; col++) {
      if (display_buf[new_display_idx][0][col] >= row)
        set_color('=', '1', &buf[idx + col * 15]);
      else
        set_color('=', '2', &buf[idx + col * 15]);

      if (display_buf[new_display_idx][1][col] >= row)
        set_color('=', '1', &buf[idx + DISPLAY_BANDS * 15 + 15 + col * 15]);
      else
        set_color('=', '2', &buf[idx + DISPLAY_BANDS * 15 + 15 + col * 15]);
    }

    set_color(' ', '2', &buf[idx + DISPLAY_BANDS * 15]);
    idx += 2 * DISPLAY_BANDS * 15 + 15;
  }

  return idx;
}

static int mono_display (int new_display_idx, char buf[21504])
{
  int row, col, idx = 0;

  for (row = DISPLAY_BARS; row > 0; row--) {
    buf[idx++] = '\n';

    for (col = 0; col < DISPLAY_BANDS; col++) {
      buf[idx + col] =
                    (display_buf[new_display_idx][0][col] >= row ? '*' : '.');
      buf[idx + col + DISPLAY_BANDS + 1] =
                    (display_buf[new_display_idx][1][col] >= row ? '*' : '.');
    }

    buf[idx + DISPLAY_BANDS] = ' ';
    idx += 2 * DISPLAY_BANDS + 1;
  }

  return idx;
}

static void start_display (struct client_worker_arg *arg,
                           int (*display_func)(int, char[21504]))
{
  /* color_display needs:
     25 bars * ((27 bands * 2 channels + space) * 15 chars + newline) = 20650
   */
  char buf[21504];
  int res, new_display_idx;

  while (1) {
    /* wake up pcm thread */
    res = pthread_cond_signal(&pcm_cond);
    if (res) {
      log_error("cannot signal pcm condition: %s", strerror(res));
      return;
    }

    res = pthread_mutex_lock(&display_mtx);
    if (res) {
      log_error("cannot lock display mutex: %s", strerror(res));
      return;
    }

    /* wait for fft thread to wake us up */
    res = pthread_cond_wait(&display_cond, &display_mtx);
    if (res) {
      log_error("cannot wait for display condition: %s", strerror(res));
      return;
    }

    res = pthread_mutex_unlock(&display_mtx);
    if (res) {
      log_error("cannot unlock display mutex: %s", strerror(res));
      return;
    }

    new_display_idx = display_idx;
    new_display_idx = 1 - new_display_idx;

    res = (*display_func)(new_display_idx, buf);

    if (write(arg->socket, buf, res) != res)
      return;
  }
}

static void log_http (struct client_worker_arg *arg, const char *url,
                      int code)
{
  log_info("%s \"%s\" %i", arg->clientname, url, code);
}

static char *http_reason (int code)
{
  switch (code) {
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    default:  return "Internal Server Error";
  }
}

static int send_http (struct client_worker_arg *arg, const char *url,
                      int code, int connection_close,
                      const char *header_and_content)
{
  char buf[sizeof("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n"
                  "Server: grapheqd/version 123\r\n\0")];
  int res;

  log_http(arg, url, code);

  snprintf(buf, sizeof(buf),
           "HTTP/1.1 %i %s\r\n"
           "%s"
           "Server: grapheqd/version " GRAPHEQD_VERSION "\r\n",
           code, http_reason(code),
           (connection_close ? "Connection: close\r\n" : ""));

  res = write(arg->socket, buf, strlen(buf));
  if ((res < 0) || (res != (signed) strlen(buf)))
    return -1;

  res = write(arg->socket, header_and_content, strlen(header_and_content));
  if ((res < 0) || (res != (signed) strlen(header_and_content)))
    return -1;

  if (connection_close) {
    close(arg->socket);
    return 1;
  }

  return 0;
}

static int read_http (struct client_worker_arg *arg)
{
  char buf[8192], *p;
  unsigned int idx = 0;
  int res, connection_close = 0;
#include "rootpage.h"
#include "favicon.h"
  const char * const websocket_header = "Upgrade: websocket\r\n"
                                        "Connection: Upgrade\r\n";

  while (idx < sizeof(buf) - 1) {
    res = read(arg->socket, &buf[idx], sizeof(buf) - idx - 1);
    if (res <= 0)
      break;

    if (buf[0] == 'm') {
      log_http(arg, "m", 200);
      pthread_setname_np(pthread_self(), "grapheqd:clientm");
      start_display(arg, &mono_display);
      return 1;
    }

    if (buf[0] == 'c') {
      log_http(arg, "c", 200);
      pthread_setname_np(pthread_self(), "grapheqd:clientc");
      sprintf(buf, "%c]2;grapheqd%c\\", 27, 27);
      if (write(arg->socket, buf, strlen(buf)) == (signed) strlen(buf))
        start_display(arg, &color_display);
      return 1;
    }

    idx += res;
    buf[idx] = '\0';

    if (!strstr(buf, "\r\n\r\n"))
      continue;

    connection_close = (strcasestr(buf, "\r\nConnection: close\r\n") != NULL);

    if (!strncasecmp(buf, "GET / ", strlen("GET / ")))
      return send_http(arg, "/", 200, connection_close, rootpage);

    if (!strncasecmp(buf, "GET /favicon.ico ", strlen("GET /favicon.ico ")))
      return send_http(arg, "/favicon.ico", 200, connection_close, favicon);

    if (!strncasecmp(buf, "GET /json ", strlen("GET /json ")) &&
        strcasestr(buf, "\r\nConnection: Upgrade\r\n") &&
        strcasestr(buf, "\r\nUpgrade: websocket\r\n")) {
      pthread_setname_np(pthread_self(), "grapheqd:clientj");
      if (!send_http(arg, "/json", 101, 0, websocket_header))
        start_display(arg, &json_display);
      return 1;
    }

    p = strchr(buf, '\r');
    *p = '\0';

    return send_http(arg, buf, 404, connection_close,
                     "Content-Type: text/plain\r\n"
                     "Content-Length: 12\r\n"
                     "\r\n"
                     "Not found.\r\n");
  }

  return send_http(arg, "", 400, connection_close,
                   "Content-Type: text/plain\r\n"
                   "Content-Length: 14\r\n"
                   "\r\n"
                   "Bad Request.\r\n");
}

static void *client_worker (void *arg0)
{
  struct client_worker_arg *arg = arg0;
  int res;

  pthread_setname_np(pthread_self(), "grapheqd:client");
  client_address(arg);
  count_client(1);

  do {
    res = read_http(arg);
  } while (res == 0);

  count_client(-1);
  close(arg->socket);

  return NULL;
}

static int create_client_worker (int listen_socket)
{
  pthread_t thread;
  struct client_worker_arg *arg;
  int res, yes;

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

  yes = 1;
  res = setsockopt(arg->socket, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
  if (res != 0) {
    log_error("cannot set keepalive for client socket: %s", strerror(res));
    close(arg->socket);
    free(arg);
    return 0;
  }

  res = pthread_create(&thread, NULL, &client_worker, arg);
  if (res != 0)
    log_error("cannot create client worker thread: %s", strerror(res));

  return res;
}

static int wait_for_client (int listen_socket)
{
  int res;
  fd_set rfds;

  FD_ZERO(&rfds);
  FD_SET(listen_socket, &rfds);

  res = select(listen_socket + 1, &rfds, NULL, NULL, NULL);

  if (res > 0) {
    res = create_client_worker(listen_socket);
  } else if (res < 0) {
    if (errno == EINTR) {
      res = 0;
    } else {
      log_error("select(): %s", strerror(errno));
    }
  }

  return res;
}

static void create_helper_worker (void *(*start_routine)(void*), void *arg,
                                  const char *name)
{
  int res;
  pthread_t thread;

  res = pthread_create(&thread, NULL, start_routine, arg);
  if (res != 0)
    errx(1, "cannot create %s worker thread: %s", name, strerror(res));
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

  create_helper_worker(&pcm_worker, soundhandle, "pcm");
  create_helper_worker(&fft_worker, fft_cfg, "fft");

  setup_signals();

  if (!foreground) {
    close(0); close(1); close(2);
  }

  openlog("grapheqd", LOG_NDELAY|LOG_PID, LOG_DAEMON);
  log_info("starting...");

#ifdef USE_SYSTEMD
  sd_notify(0, "READY=1");
#endif

  while (running) {
    res = wait_for_client(listen_socket);
    if (res < 0)
      running = 0;
  }

  snd_pcm_close(soundhandle);
  close(listen_socket);

  if (pidfile)
    unlink(pidfile); /* may fail, e.g. due to changed user privs */

  log_info("exiting...");
  closelog();

  return 0;
}
