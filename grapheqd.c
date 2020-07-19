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
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <sys/uio.h>
#ifdef USE_OSS
#  include <pthread_np.h>
#  include <sys/ioctl.h>
#  include <sys/soundcard.h>
#else
#  include <alsa/asoundlib.h>
#endif
#include <openssl/sha.h>
#include "kiss_fft.h"
#ifdef USE_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif

#define GRAPHEQD_VERSION "2"

#define MAX_CHANNELS 2    /* stereo */
#define SAMPLING_WIDTH 2  /* 16 bit signed per channel per sample */
#define SAMPLING_FORMAT SND_PCM_FORMAT_S16 /* keep in sync to SAMPLING_WIDTH
                                              and every use of int16_t */
#define DISPLAY_BANDS 27 /* 27 horizontal bands/buckets per channel
                            displayed */
#define DISPLAY_BARS 25  /* 25 vertical segments per band */
#define FFT_SIZE 4096    /* must be power of 2   */

#define log_error(fmt, params ...) do { \
  if (foreground) \
    warnx("%s (%s:%i): " fmt, \
          __FUNCTION__, __FILE__, __LINE__, ## params); \
  else \
    syslog(LOG_ERR, "%s (%s:%i): " fmt "\n", \
           __FUNCTION__, __FILE__, __LINE__, ## params); \
} while (0)

#define log_warn(fmt, params ...) do { \
  if (foreground) \
    warnx("%s (%s:%i): " fmt, \
          __FUNCTION__, __FILE__, __LINE__, ## params); \
  else \
    syslog(LOG_WARNING, "%s (%s:%i): " fmt "\n", \
           __FUNCTION__, __FILE__, __LINE__, ## params); \
} while (0)

#define log_info(fmt, params ...) do { \
  if (foreground) printf(fmt "\n", ## params); \
  else syslog(LOG_INFO, fmt "\n", ## params); \
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

/* a peak value per channel and band within display_buf */
typedef struct {
  unsigned char value;
  char duration;
} peak;

static int pcm_idx = 0;
static int16_t pcm_buf[2][FFT_SIZE * MAX_CHANNELS];
static pthread_mutex_t pcm_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pcm_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t fft_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fft_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t display_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t display_cond = PTHREAD_COND_INITIALIZER;
static int display_idx = 0;
static unsigned char display_buf[2][MAX_CHANNELS][DISPLAY_BANDS];
static int num_clients = 0;
static pthread_mutex_t num_mtx = PTHREAD_MUTEX_INITIALIZER;
/* set by alsa_open() */
static int sampling_rate;
static int sampling_channels;

/* used by main() and quitterm_handler() */
static int running = 1;
/* used by main() and log_*() macros */
static int foreground = 0;

static void quitterm_handler (int sig)
{
  if (sig == SIGTERM)
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
    err(1, "sigdelset(SIGTERM)");

  if (sigdelset(&sigset, SIGQUIT) != 0)
    err(1, "sigdelset(SIGQUIT)");

  if (pthread_sigmask(SIG_SETMASK, &sigset, NULL) != 0)
    err(1, "pthread_sigmask()");

  setup_signal(SIGTERM, quitterm_handler);
  setup_signal(SIGQUIT, quitterm_handler);
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

void thread_setname (const char *name)
{
#ifdef USE_OSS
  pthread_set_name_np(pthread_self(), name);
#else
  pthread_setname_np(pthread_self(), name);
#endif
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

static void fft_mono (kiss_fft_cfg fft_cfg)
{
  int i, new_pcm_idx;
  kiss_fft_cpx lin[FFT_SIZE];
  kiss_fft_cpx lout[FFT_SIZE];
  float llevel[FFT_SIZE / 2];
  /* kiss_fft emits 131072 when fed with a pure sine, so it's a good starting
     point */
  static float max_level = 131072.;

  new_pcm_idx = pcm_idx;
  new_pcm_idx = 1 - new_pcm_idx;

  for (i = 0; i < FFT_SIZE; i++) {
    /* left channel */
    lin[i].r = pcm_buf[new_pcm_idx][2 * i];
    lin[i].i = 0;
  }

  kiss_fft(fft_cfg, &lin[0], &lout[0]);

  for (i = 0; i < FFT_SIZE / 2; i++) {
    llevel[i] = calculate_power(lout[i], &max_level);
  }

  fill_bands(&llevel, max_level, &display_buf[display_idx][0]);

  for (i = 0; i < DISPLAY_BANDS; i++)
    display_buf[display_idx][1][i] = display_buf[display_idx][0][i];
}

static void fft_stereo (kiss_fft_cfg fft_cfg)
{
  int i, new_pcm_idx;
  kiss_fft_cpx lin[FFT_SIZE], rin[FFT_SIZE];
  kiss_fft_cpx lout[FFT_SIZE], rout[FFT_SIZE];
  float llevel[FFT_SIZE / 2], rlevel[FFT_SIZE / 2];
  /* kiss_fft emits 131072 when fed with a pure sine, so it's a good starting
     point */
  static float max_level = 131072.;

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
}

static void *fft_worker (void *arg0)
{
  kiss_fft_cfg fft_cfg = (kiss_fft_cfg) arg0;
  int res;

  thread_setname("grapheqd:fft");

  res = pthread_mutex_lock(&fft_mtx);
  if (res) {
    log_error("cannot lock fft mutex: %s", strerror(res));
    goto ERROR;
  }

  while (running) {
    /* wait for pcm thread to wake us up */
    res = pthread_cond_wait(&fft_cond, &fft_mtx);
    if (res) {
      log_error("cannot wait for fft condition: %s", strerror(res));
      break;
    }

    if (sampling_channels == 1)
      fft_mono(fft_cfg);
    else
      fft_stereo(fft_cfg);

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

ERROR:
  kill(getpid(), SIGQUIT);

  return NULL;
}

#ifdef USE_OSS
static int pcm_worker_loop (void *arg0)
{
  int *soundhandle = arg0;
  ssize_t num_bytes;
  int res;

  while (num_clients > 0) {
    num_bytes = read(*soundhandle, &pcm_buf[pcm_idx],
                     FFT_SIZE * sampling_channels);
    if (num_bytes < 0) {
      log_error("cannot read pcm data: %s", strerror(errno));
      return -1;
    }

    if (num_bytes != FFT_SIZE * sampling_channels) {
      log_warn("read %li bytes of pcm data instead of %i", num_bytes,
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
#else /* ^USE_OSS / v!USE_OSS */
static int pcm_worker_loop (void *arg0)
{
  snd_pcm_t *soundhandle = arg0;
  snd_pcm_sframes_t num_frames;
  int res;

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
      log_warn("read %li bytes of pcm data instead of %i", num_frames,
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
#endif /* !USE_OSS */

static void *pcm_worker (void *arg0)
{
  int res;

  thread_setname("grapheqd:pcm");

  res = pthread_mutex_lock(&pcm_mtx);
  if (res) {
    log_error("cannot lock pcm mutex: %s", strerror(res));
    goto ERROR;
  }

  while (running) {
    /* wait for a client thread to wake us up */
    res = pthread_cond_wait(&pcm_cond, &pcm_mtx);
    if (res) {
      log_error("cannot wait for pcm condition: %s", strerror(res));
      break;
    }

    if (pcm_worker_loop(arg0))
      break;
  }

  res = pthread_mutex_unlock(&pcm_mtx);
  if (res)
    log_error("cannot unlock pcm mutex: %s", strerror(res));

ERROR:
  kill(getpid(), SIGQUIT);

  return NULL;
}

static int count_client (int i)
{
  int res;

  res = pthread_mutex_lock(&num_mtx);
  if (res) {
    log_warn("cannot lock num_clients mutex: %s", strerror(res));
    return res;
  }

  num_clients += i;

  res = pthread_mutex_unlock(&num_mtx);
  if (res)
    log_warn("cannot unlock num_clients mutex: %s", strerror(res));

  return res;
}

static char *str2buf (char *buf, const char * const str, size_t l)
{
  memcpy(buf, str, l - 1);
  return buf + l - 1;
}

static void int2buf (char *buf, int i, int len)
{
  char *p = buf, *start = buf - len;

  while (p > start) {
    *p-- = '0' + i % 10;
    i /= 10;
    if (i == 0)
      break;
  }
  while (p > start)
    *p-- = ' ';
}

static char *json_display (int new_display_idx,
                           peak (*peaks)[MAX_CHANNELS][DISPLAY_BANDS],
                           char *buf)
{
  char *p = buf;
  int col;
  const char ws_json[] = "\x81\x7e\x1\x92"
                         "{\"rate\":44100,\"channels\":2,\n"
                         "\"left\":[25,25,25,25,25,25,25,25,25,25,25,25,"
                         "25,25,25,25,25,25,25,25,25,25,25,25,25,25,25],\n"
                         "\"right\":[25,25,25,25,25,25,25,25,25,25,25,25,"
                         "25,25,25,25,25,25,25,25,25,25,25,25,25,25,25],\n"
                         "\"peakleft\":[25,25,25,25,25,25,25,25,25,25,25,25,"
                         "25,25,25,25,25,25,25,25,25,25,25,25,25,25,25],\n"
                         "\"peakright\":[25,25,25,25,25,25,25,25,25,25,25,25,"
                         "25,25,25,25,25,25,25,25,25,25,25,25,25,25,25]}\n";

  p = str2buf(p, ws_json, sizeof(ws_json));

  int2buf(p - 390, sampling_rate, 5);
  int2buf(p - 377, sampling_channels, 1);

  for (col = 0; col < DISPLAY_BANDS; col++) {
    int2buf(p - 365 + col * 3, display_buf[new_display_idx][0][col], 2);
    int2buf(p - 273 + col * 3, display_buf[new_display_idx][1][col], 2);
    int2buf(p - 178 + col * 3, (*peaks)[0][col].value, 2);
    int2buf(p - 82 + col * 3, (*peaks)[1][col].value, 2);
  }

  return p;
}

static char *green_on_black (char bright, char *buf)
{
  char *p = buf;
  static char old_bright = -1;
  const char esc_seq[] = "\x1b[0m\x1b[ ;36;40m";

  if (old_bright != bright) {
    p = str2buf(p, esc_seq, sizeof(esc_seq));
    *(p - 8) = (bright ? '1' : '2');
    old_bright = bright;
  }

  return p;
}

static char *color_display (int new_display_idx,
                            peak (*peaks)[MAX_CHANNELS][DISPLAY_BANDS],
                            char *buf)
{
  char *p = buf;
  int row, col;
  const char status_line[] = "\n    \x1b[0m\x1b[ ;36;40mMono      "
                             "\x1b[0m\x1b[ ;36;40mStereo         "
                             "\x1b[0m\x1b[ ;36;40m44100 Hz      "
                             "\x1b[0m\x1b[ ;36;40m48000 Hz    ";

  for (row = DISPLAY_BARS; row > 0; row--) {
    *p++ = '\n';

    for (col = 0; col < DISPLAY_BANDS; col++) {
      int bright = (display_buf[new_display_idx][0][col] >= row) ||
                   ((*peaks)[0][col].value == row);
      p = green_on_black(bright, p);
      *p++ = '=';
    }

    p = green_on_black(0, p);
    *p++ = ' ';

    for (col = 0; col < DISPLAY_BANDS; col++) {
      int bright = (display_buf[new_display_idx][1][col] >= row) ||
                   ((*peaks)[1][col].value == row);
      p = green_on_black(bright, p);
      *p++ = '=';
    }
  }

  p = str2buf(p, status_line, sizeof(status_line));
  *(p - 101) = (sampling_channels == 2 ? '2' : '1');
  *(p - 77) = (sampling_channels == 2 ? '1' : '2');
  *(p - 48) = (sampling_rate == 44100 ? '1' : '2');
  *(p - 20) = (sampling_rate == 44100 ? '2' : '1');
  /* otherwise old_bright will not reflect latest color mode */
  green_on_black((sampling_rate != 44100), p - 26);

  return p;
}

static char *mono_display (int new_display_idx,
                           peak (*peaks)[MAX_CHANNELS][DISPLAY_BANDS],
                           char *buf)
{
  char *p = buf;
  int row, col;
  const char status_line[] = "\n  [ ] Mono  [ ] Stereo     "
                             "[ ] 44100 Hz  [ ] 48000 Hz  ";

  for (row = DISPLAY_BARS; row > 0; row--) {
    *p++ = '\n';

    for (col = 0; col < DISPLAY_BANDS; col++) {
      *(p + col) =
                ((display_buf[new_display_idx][0][col] >= row) ||
                 ((*peaks)[0][col].value == row) ? '*' : '.');
      *(p + col + DISPLAY_BANDS + 1) =
                ((display_buf[new_display_idx][1][col] >= row) ||
                 ((*peaks)[1][col].value == row) ? '*' : '.');
    }

    *(p + DISPLAY_BANDS) = ' ';
    p += 2 * DISPLAY_BANDS + 1;
  }

  p = str2buf(p, status_line, sizeof(status_line));
  *(p - 52) = (sampling_channels == 2 ? ' ' : 'X');
  *(p - 42) = (sampling_channels == 2 ? 'X' : ' ');
  *(p - 27) = (sampling_rate == 44100 ? 'X' : ' ');
  *(p - 13) = (sampling_rate == 44100 ? ' ' : 'X');

  return p;
}

static void calculate_peaks (unsigned char (*display)[DISPLAY_BANDS],
                             peak (*peaks)[DISPLAY_BANDS])
{
  int col;

  for (col = 0; col < DISPLAY_BANDS; col++) {
    if ((*display)[col] >= (*peaks)[col].value) {
      (*peaks)[col].value = (*display)[col];
      (*peaks)[col].duration = 0;
    } else if ((*peaks)[col].duration >= 5) {
      (*peaks)[col].value--;
      (*peaks)[col].duration = 4;
    } else {
      (*peaks)[col].duration++;
    }
  }
}

static void start_display (struct client_worker_arg *arg,
                           char * (*display_func)(int,
                                        peak (*)[MAX_CHANNELS][DISPLAY_BANDS],
                                        char *))
{
  /* color_display needs:
     (25 bars + status line) *
     ((27 bands * 2 channels + space) * 15 chars + newline) = 21476 */
  char buf[21504], *p;
  int res, new_display_idx;
  peak peaks[MAX_CHANNELS][DISPLAY_BANDS] = { 0 };

  while (1) {
    /* wake up pcm thread */
    res = pthread_cond_signal(&pcm_cond);
    if (res) {
      log_warn("cannot signal pcm condition: %s", strerror(res));
      return;
    }

    res = pthread_mutex_lock(&display_mtx);
    if (res) {
      log_warn("cannot lock display mutex: %s", strerror(res));
      return;
    }

    /* wait for fft thread to wake us up */
    res = pthread_cond_wait(&display_cond, &display_mtx);
    if (res) {
      log_warn("cannot wait for display condition: %s", strerror(res));
      return;
    }

    res = pthread_mutex_unlock(&display_mtx);
    if (res) {
      log_warn("cannot unlock display mutex: %s", strerror(res));
      return;
    }

    new_display_idx = display_idx;
    new_display_idx = 1 - new_display_idx;

    calculate_peaks(&display_buf[new_display_idx][0], &peaks[0]);
    calculate_peaks(&display_buf[new_display_idx][1], &peaks[1]);

    p = (*display_func)(new_display_idx, &peaks, buf);

    if (write(arg->socket, buf, p - buf) != p - buf)
      return;
  }
}

static void log_http (struct client_worker_arg *arg, const char *url,
                      int code)
{
  log_info("%s \"%s\" %i", arg->clientname, url, code);
}

static int send_http (struct client_worker_arg *arg, const char *url,
                      int code, int connection_close,
                      char *header_and_content, size_t header_content_size)
{
  const char status_line[] = "HTTP/1.1 200 ";
  char server_line[] = "\r\nServer: grapheqd/version " GRAPHEQD_VERSION
                             "\r\n";
  char connection_line[] = "Connection: close\r\n";
  char buf[16], *p;
  int res, idx;
  struct iovec iov[5];
  ssize_t len;

  log_http(arg, url, code);

  p = str2buf(buf, status_line, sizeof(status_line));
  int2buf(p - 2, code, 3);
  iov[0].iov_base = buf;
  iov[0].iov_len = sizeof(status_line) - 1;
  len = sizeof(status_line) - 1;

  switch (code) {
    case 101:
      iov[1].iov_base = "Switching Protocols";
      break;
    case 200:
      iov[1].iov_base = "OK";
      break;
    case 400:
      iov[1].iov_base = "Bad Request";
      break;
    case 404:
      iov[1].iov_base = "Not Found";
      break;
    default:
      iov[1].iov_base = "Internal Server Error";
      break;
  }
  iov[1].iov_len = strlen(iov[1].iov_base);
  len += strlen(iov[1].iov_base);

  iov[2].iov_base = server_line;
  iov[2].iov_len = sizeof(server_line) - 1;
  len += sizeof(server_line) - 1;

  if (connection_close) {
    iov[3].iov_base = connection_line;
    iov[3].iov_len = sizeof(connection_line) - 1;
    len += sizeof(connection_line) - 1;
    idx = 4;
  } else {
    idx = 3;
  }

  iov[idx].iov_base = header_and_content;
  iov[idx++].iov_len = header_content_size;
  len += header_content_size;

  res = writev(arg->socket, iov, idx);
  if ((res < 0) || (res != len))
    return -1;

  if (connection_close) {
    close(arg->socket);
    return 1;
  }

  return 0;
}

/* encode len bytes from src to dst */
static void base64 (char *dst, unsigned char *src, int len)
{
  const char tbl[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "abcdefghijklmnopqrstuvwxyz0123456789+/";
  int i, j;

  for (i = 0, j = 0; i < len; ++i) {
    *(dst + j++) = tbl[(*(src + i) >> 2) & 63];
    *(dst + j++) = tbl[((*(src + i) << 4) + (*(src + i + 1) >> 4)) & 63];
    if (++i == len) break;
    *(dst + j++) = tbl[((*(src + i) << 2) + (*(src + i + 1) >> 6)) & 63];
    if (++i == len) break;
    *(dst + j++) = tbl[*(src + i) & 63];
  }

  while ((j % 4)) *(dst + j++) = '=';
}

static void start_websocket(struct client_worker_arg *arg, char *url,
                           char *ws_key,
                           char * (*display_func)(int,
                                        peak (*)[MAX_CHANNELS][DISPLAY_BANDS],
                                        char *))
{
  const char ws_uuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const char websocket_header[] = "Upgrade: websocket\r\n"
                                  "Sec-WebSocket-Accept: "
                                            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                  "Connection: Upgrade\r\n\r\n";
  char buf[sizeof(websocket_header)];
  unsigned char sha_md[SHA_DIGEST_LENGTH];
  SHA_CTX sha_ctx;
  char *line_end = strchr(ws_key, '\r');

  if (!line_end)
    /* cant happen, has_header() checks for end of line as well */
    return;
  if (!SHA1_Init(&sha_ctx))
    return;
  if (!SHA1_Update(&sha_ctx, ws_key, line_end - ws_key))
    return;
  if (!SHA1_Update(&sha_ctx, ws_uuid, sizeof(ws_uuid) - 1))
    return;
  if (!SHA1_Final(sha_md, &sha_ctx))
    return;

  str2buf(buf, websocket_header, sizeof(websocket_header));
  base64(buf + 42, sha_md, sizeof(sha_md));

  if (!send_http(arg, url, 101, 0, buf, sizeof(websocket_header) - 1))
    start_display(arg, display_func);
}

static char *has_header (char *buf, char *name, char *value)
{
  char *p = buf, *line_end, *found;

  while (*p) {
    /* search header name in http header */
    p = strcasestr(p, name);
    if (!p)
      return NULL;

    if ((p == buf) || (*(p - 1) != '\n')) {
      p += strlen(name);
      continue;
    }

    p += strlen(name); /* p is now on the colon or '\0' */
    if ((*p == ':') && (*(p + 1) == ' '))
      break;
  }

  if (!p || !*p)
    return NULL;

  p += 2;
  /* p is now on first value of header option, or \r or \0 */

  line_end = strchr(p, '\r');
  if (!line_end || (p == line_end))
    return NULL;

  /* not interested in particular value of this header option, just return
     pointer to beginning of values */
  if (!value)
    return p;

  /* XXX check for separate values */
  found = strcasestr(p, value);
  if (!found || (found >= line_end))
    return NULL;

  return found;
}

static int read_http (struct client_worker_arg *arg)
{
  char buf[8192], *p, *ws_key;
  unsigned int idx = 0;
  int res, connection_close = 0;
#include "rootpage.h"
#include "favicon.h"
  const char term_title[] = "\x1b]2;grapheqd\x1b\\";
  char not_found[] = "Content-Type: text/plain\r\n"
                     "Content-Length: 12\r\n"
                     "\r\n"
                     "Not found.\r\n";
  char bad_request[] = "Content-Type: text/plain\r\n"
                       "Content-Length: 14\r\n"
                       "\r\n"
                       "Bad Request.\r\n";

  while (idx < sizeof(buf) - 1) {
    res = read(arg->socket, &buf[idx], sizeof(buf) - idx - 1);
    if (res <= 0)
      return -1;

    if (buf[0] == 'm') {
      log_http(arg, "m", 200);
      start_display(arg, &mono_display);
      return 1;
    }

    if (buf[0] == 'c') {
      log_http(arg, "c", 200);
      res = write(arg->socket, term_title, sizeof(term_title) - 1);
      if (res == (signed) sizeof(term_title) - 1)
        start_display(arg, &color_display);
      return 1;
    }

    idx += res;
    buf[idx] = '\0';

    if (!strstr(buf, "\r\n\r\n"))
      continue;

    connection_close = (strcasestr(buf, "\r\nConnection: close\r\n") != NULL);

    if (!strncasecmp(buf, "GET / ", strlen("GET / ")))
      return send_http(arg, "/", 200, connection_close, rootpage,
                       sizeof(rootpage));

    if (!strncasecmp(buf, "GET /favicon.ico ", strlen("GET /favicon.ico ")))
      return send_http(arg, "/favicon.ico", 200, connection_close, favicon,
                       sizeof(favicon));

    if (!strncasecmp(buf, "GET /json ", strlen("GET /json ")) &&
        has_header(buf, "Connection", "Upgrade") &&
        has_header(buf, "Upgrade", "websocket") &&
        ((ws_key = has_header(buf, "Sec-WebSocket-Key", NULL)) != NULL)) {
      start_websocket(arg, "/json", ws_key, &json_display);
      return 1;
    }

    p = strchr(buf, '\r');
    *p = '\0';

    return send_http(arg, buf, 404, connection_close, not_found,
                     sizeof(not_found) - 1);
  }

  return send_http(arg, "", 400, connection_close, bad_request,
                   sizeof(bad_request) - 1);
}

static void *client_worker (void *arg0)
{
  struct client_worker_arg *arg = arg0;
  int res;

  thread_setname("grapheqd:client");

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
    log_warn("accept(): %s", strerror(errno));
    free(arg);
    return 0;
  }

  yes = 1;
  res = setsockopt(arg->socket, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
  if (res != 0) {
    log_warn("cannot set keepalive for client socket: %s", strerror(res));
    close(arg->socket);
    free(arg);
    return 0;
  }

  res = pthread_create(&thread, NULL, &client_worker, arg);
  if (res != 0) {
    log_error("cannot create client worker thread: %s", strerror(res));
    close(arg->socket);
    free(arg);
    return res;
  }

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

#ifdef USE_OSS
static int *open_sound (const char *soundcard)
{
  int *fd;
  int format = AFMT_S16_LE;
  int res;

  if (!soundcard)
    soundcard = "/dev/dsp0";

  fd = malloc(sizeof(*fd));
  if (fd == NULL)
    errx(1, "malloc(): out of memory");

  *fd = open(soundcard, O_RDONLY);
  if (*fd < 0)
    err(1, "cannot open %s for capturing", soundcard);

  if (ioctl(*fd, SNDCTL_DSP_SETFMT, &format) == -1)
    err(1, "SNDCTL_DSP_SETFMT(AFTM_S16_LE)");

  sampling_channels = 2;
  res = ioctl(*fd, SNDCTL_DSP_CHANNELS, &sampling_channels);
  if (res == -1) {
    sampling_channels = 1;
    res = ioctl(*fd, SNDCTL_DSP_CHANNELS, &sampling_channels);
  }
  if (res == -1)
    err(1, "SNDCTL_DSP_CHANNELS(2 or 1)");

  sampling_rate = 44100;
  res = ioctl(*fd, SNDCTL_DSP_SPEED, &sampling_rate);
  if (res == -1) {
    sampling_rate = 48000;
    res = ioctl(*fd, SNDCTL_DSP_SPEED, &sampling_rate);
  }
  if (res == -1)
    err(1, "SNDCTL_DSP_SPEED(44100 or 48000)");

  return fd;
}

void close_sound (void *soundptr)
{
  int *fd = soundptr;
  close(*fd);
  free(fd);
}
#else /* ^USE_OSS / v!USE_OSS */
static void *open_sound (const char *soundcard)
{
  snd_pcm_t *handle;
  snd_pcm_hw_params_t *params;
  int err;
  snd_pcm_format_t format;

  if (!soundcard)
    soundcard = "hw:0";

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
    warnx("%s: %s", "snd_pcm_hw_params_set_format(" STR(SAMPLING_WIDTH) ")",
                    snd_strerror(err));

  err = snd_pcm_hw_params_get_format(params, &format);
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_get_format()", snd_strerror(err));

  if (format != SAMPLING_WIDTH)
    errx(1, "sampling format is %i, not " STR(SAMPLING_FORMAT), format);

  sampling_channels = 2;
  err = snd_pcm_hw_params_set_channels(handle, params, 2);
  if (err) {
    sampling_channels = 1;
    err = snd_pcm_hw_params_set_channels(handle, params, 1);
  }
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_channels(2 or 1)",
                      snd_strerror(err));

  sampling_rate = 44100;
  err = snd_pcm_hw_params_set_rate(handle, params, 44100, 0);
  if (err) {
    sampling_rate = 48000;
    err = snd_pcm_hw_params_set_rate(handle, params, 48000, 0);
  }
  if (err)
    errx(1, "%s: %s", "snd_pcm_hw_params_set_rate(44100 or 48000)",
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

void close_sound (void *soundptr)
{
  snd_pcm_close((snd_pcm_t*) soundptr);
}
#endif /* !USE_OSS */

static void show_help ()
{
  puts(
"graphedq version " GRAPHEQD_VERSION "\n"
"PCM driver: "
#ifdef USE_OSS
"OSS"
#else
"ALSA"
#endif
"\n"
"\n"
"Usage:\n"
"grapheqd [-a <address>] [-d] [-l <port>] [-p <pid file>] [-s <soundcard>]\n"
"         [-u <user>]\n"
"grapheqd -h\n"
"\n"
"  -a <address>        listen on this address; default: 0.0.0.0\n"
"  -d                  run in foreground, and log to stdout/stderr, do not\n"
"                      detach from terminal, do not log to syslog\n"
"  -l <port>           listen on this port; default: 8083\n"
"  -p <pid file>       daemonize and save pid to this file; no default, pid\n"
"                      gets not written to any file\n"
"  -s <soundcard>      read PCM from this soundcard; default: "
#ifdef USE_OSS
"/dev/dsp0"
#else
"hw:0"
#endif
"\n"
"  -u <user>           switch to this user; no default, run as invoking user\n"
"  -h                  show this help ;-)\n"
);
}

int main (int argc, char **argv)
{
  int res, listen_socket;
  char *address = "0.0.0.0", *port = "8083", *pidfile = NULL,
       *soundcard = NULL;
  struct passwd *user = NULL;
  void *soundptr;
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
  soundptr = open_sound(soundcard);

  if (!foreground)
    daemonize();

  if (pidfile)
    save_pidfile(pidfile);

  if (user)
    change_user(user);

  fft_cfg = kiss_fft_alloc(FFT_SIZE, 0, NULL, NULL);
  if (!fft_cfg)
    errx(1, "cannot initialize FFT state");

  create_helper_worker(&pcm_worker, soundptr, "pcm");
  create_helper_worker(&fft_worker, fft_cfg, "fft");

  setup_signals();

  if (!foreground) {
    openlog("grapheqd", LOG_NDELAY|LOG_PID, LOG_DAEMON);
    close(0); close(1); close(2);
  }

  log_info("starting...");

#ifdef USE_SYSTEMD
  sd_notify(0, "READY=1");
#endif

  while (running) {
    res = wait_for_client(listen_socket);
    if (res < 0)
      running = 0;
  }

  close_sound(soundptr);
  close(listen_socket);

  if (pidfile)
    unlink(pidfile); /* may fail, e.g. due to changed user privs */

  log_info("exiting...");
  if (!foreground)
    closelog();

  return 0;
}
