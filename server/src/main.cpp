// keystorkd -- the on-device half of keystork.
//
// A fork-per-connection supervisor. It owns nothing but the listening socket:
// every connection becomes a child that permanently drops to the UID named in
// the handshake, opens its own Binder connection, serves requests
// synchronously, and dies with the connection. There is no worker pool, and a
// child is never reused for a second UID -- that is the one line this design
// must not cross, because it would reintroduce exactly the cross-UID
// contamination the model exists to prevent.
//
// Launch as root on a device you control. There is no authentication.

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"
#include "session.h"

namespace {

constexpr char kDefaultSocketName[] = "keystork";
constexpr int kDefaultMaxSessions = 16;
constexpr int kListenBacklog = 8;

// A peer's `unix_stream_socket connectto` check is evaluated against the
// context of the *socket*, which a socket inherits from whoever created it.
// Running under su leaves that a root domain adbd is not allowed to reach, so
// `adb forward` fails on a device that is enforcing. Labelling the listening
// socket as the shell domain instead is the pairing adb already uses for every
// ordinary `adb forward localabstract:`.
constexpr char kDefaultSocketContext[] = "u:r:shell:s0";

// `--tcp PORT` with no address binds every interface; `--tcp ADDR:PORT` picks
// one.
constexpr char kDefaultTcpAddress[] = "0.0.0.0";

// Written by the SIGCHLD handler, read by the accept loop.
volatile sig_atomic_t g_reaped = 0;

// Set by SIGTERM, which is how a kill_server child asks the supervisor to stop.
volatile sig_atomic_t g_terminate = 0;

void HandleSigchld(int /*signo*/) {
  const int saved_errno = errno;
  while (::waitpid(-1, nullptr, WNOHANG) > 0) g_reaped++;
  errno = saved_errno;
}

void HandleSigterm(int /*signo*/) { g_terminate = 1; }

bool InstallSignalHandlers() {
  struct sigaction sa {};
  sa.sa_handler = HandleSigchld;
  sigemptyset(&sa.sa_mask);
  // SA_RESTART keeps accept() from unwinding every time a session ends.
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  if (::sigaction(SIGCHLD, &sa, nullptr) != 0) return false;

  // Deliberately *without* SA_RESTART: this one has to break accept() so the
  // loop notices g_terminate rather than blocking until the next connection.
  struct sigaction term {};
  term.sa_handler = HandleSigterm;
  sigemptyset(&term.sa_mask);
  term.sa_flags = 0;
  if (::sigaction(SIGTERM, &term, nullptr) != 0) return false;

  // A client that hangs up mid-response must give the child an EPIPE to
  // handle, not kill it outright.
  struct sigaction ignore {};
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  return ::sigaction(SIGPIPE, &ignore, nullptr) == 0;
}

// Detaches from the launching shell: fork so this is not a process-group
// leader, setsid to leave the controlling terminal, fork again so the daemon
// can never reacquire one, then give up the caller's working directory and
// stdio. Called only after the socket is bound, so a bind failure is still
// reported to whoever ran the command rather than vanishing.
bool Daemonize() {
  pid_t pid = ::fork();
  if (pid < 0) return false;
  if (pid > 0) ::_exit(0);  // the caller's command returns here

  if (::setsid() < 0) return false;

  pid = ::fork();
  if (pid < 0) return false;
  if (pid > 0) ::_exit(0);

  // Holding the caller's cwd would pin whatever it is mounted on.
  if (::chdir("/") != 0) return false;

  const int null_fd = ::open("/dev/null", O_RDWR | O_CLOEXEC);
  if (null_fd < 0) return false;
  ::dup2(null_fd, STDIN_FILENO);
  ::dup2(null_fd, STDOUT_FILENO);
  ::dup2(null_fd, STDERR_FILENO);
  if (null_fd > STDERR_FILENO) ::close(null_fd);
  return true;
}

// Every live session is a child in this process group, so one signal ends them
// all. The group is the daemon's own -- see setpgid in main() -- so this cannot
// reach the shell that launched it. SIGTERM is ignored first because the
// supervisor is in the group too.
void TerminateSessions() {
  ::signal(SIGTERM, SIG_IGN);
  if (::kill(0, SIGTERM) != 0) KS_LOGE("could not signal sessions: %s", ::strerror(errno));
}

// Sets the context every socket this thread creates from here on is labelled
// with. A lone newline is how the interface is cleared; anything else is parsed
// as a context and refused if policy will not let this domain create it. This
// is what libselinux's setsockcreatecon() writes, done directly because
// libselinux is a platform library the NDK does not ship.
bool SetSocketCreateContext(const char* context) {
  const int fd = ::open("/proc/thread-self/attr/sockcreate", O_WRONLY | O_CLOEXEC);
  if (fd < 0) return false;
  const size_t length = ::strlen(context);
  const ssize_t written = ::write(fd, context, length);
  const int saved_errno = errno;
  ::close(fd);
  errno = saved_errno;
  return written == static_cast<ssize_t>(length);
}

// Binds to an abstract unix socket (leading NUL), so there is no filesystem
// entry to collide with or clean up. `adb forward tcp:<port> localabstract:<name>`
// bridges it to the host.
int ListenUnix(const std::string& name, const std::string& context) {
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (name.size() + 1 > sizeof(addr.sun_path)) {
    KS_LOGE("socket name '%s' is too long", name.c_str());
    return -1;
  }
  ::memcpy(addr.sun_path + 1, name.data(), name.size());
  const socklen_t addr_len =
      static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());

  // A socket's context is fixed when it is created, so this brackets the
  // socket() call as tightly as possible and is cleared straight after --
  // leaving it set would silently label every later socket too.
  if (!context.empty() && !SetSocketCreateContext(context.c_str())) {
    KS_LOGE("could not label sockets as '%s': %s -- falling back to this process's own context, "
            "which adbd may not be permitted to connect to",
            context.c_str(), ::strerror(errno));
  }
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  const int socket_errno = errno;
  if (!context.empty()) SetSocketCreateContext("\n");

  if (fd < 0) {
    KS_LOGE("socket: %s", ::strerror(socket_errno));
    return -1;
  }
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), addr_len) != 0) {
    KS_LOGE("bind to abstract socket '%s': %s", name.c_str(), ::strerror(errno));
    ::close(fd);
    return -1;
  }
  if (::listen(fd, kListenBacklog) != 0) {
    KS_LOGE("listen: %s", ::strerror(errno));
    ::close(fd);
    return -1;
  }
  return fd;
}

// Splits `[ADDR:]PORT` into its two halves. An IPv6 literal must be bracketed,
// `[::1]:9432`, so its own colons cannot be mistaken for the port separator.
bool SplitHostPort(const std::string& spec, std::string* host, std::string* port) {
  if (!spec.empty() && spec.front() == '[') {
    const size_t close = spec.find(']');
    if (close == std::string::npos || close + 1 >= spec.size() || spec[close + 1] != ':') {
      KS_LOGE("'%s' is not [ADDR]:PORT", spec.c_str());
      return false;
    }
    *host = spec.substr(1, close - 1);
    *port = spec.substr(close + 2);
  } else {
    const size_t colon = spec.rfind(':');
    if (colon == std::string::npos) {
      *host = kDefaultTcpAddress;
      *port = spec;
    } else {
      *host = spec.substr(0, colon);
      *port = spec.substr(colon + 1);
    }
  }
  if (port->empty()) {
    KS_LOGE("'%s' names no port", spec.c_str());
    return false;
  }
  return true;
}

// Binds a TCP listener described by `[ADDR:]PORT`. The address is resolved
// rather than parsed, so a hostname works as well as a literal, and the family
// follows whatever it resolves to.
int ListenTcp(const std::string& spec, std::string* description) {
  std::string host, port;
  if (!SplitHostPort(spec, &host, &port)) return -1;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  addrinfo* results = nullptr;
  const int error = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &results);
  if (error != 0) {
    KS_LOGE("could not resolve '%s' port %s: %s", host.c_str(), port.c_str(),
            ::gai_strerror(error));
    return -1;
  }

  int fd = -1;
  for (const addrinfo* ai = results; ai != nullptr; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) continue;

    // A session that was still open when the daemon was killed leaves the port
    // in TIME_WAIT, and without this the restart would fail to bind.
    const int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (::bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && ::listen(fd, kListenBacklog) == 0) break;
    KS_LOGE("bind/listen on %s port %s: %s", host.c_str(), port.c_str(), ::strerror(errno));
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(results);

  if (fd >= 0) *description = "tcp " + host + " port " + port;
  return fd;
}

void Usage(const char* argv0) {
  ::fprintf(stderr,
            "usage: %s [--socket NAME | --tcp [ADDR:]PORT] [--socket-context CONTEXT]\n"
            "          [--max-sessions N] [--daemonize]\n"
            "\n"
            "  --socket NAME        abstract unix socket to listen on (default: %s)\n"
            "  --tcp [ADDR:]PORT    listen on TCP instead of a unix socket. ADDR defaults\n"
            "                       to %s; an IPv6 literal is bracketed, [::1]:9432.\n"
            "  --socket-context CTX SELinux context to label the unix socket with, so adbd\n"
            "                       is allowed to connect to it (default: %s). Empty to\n"
            "                       leave the socket in this process's own context.\n"
            "  --max-sessions N     concurrent sessions to allow (default: %d)\n"
            "  --daemonize, -d      detach and return once the socket is bound. stderr is\n"
            "                       gone after that, so read logs with:\n"
            "                         adb logcat -s keystorkd\n"
            "\n"
            "Run as root. Bridge a unix socket to a host with:\n"
            "  adb forward tcp:9432 localabstract:%s\n"
            "A TCP listener is reached directly, or through:\n"
            "  adb forward tcp:9432 tcp:9432\n",
            argv0, kDefaultSocketName, kDefaultTcpAddress, kDefaultSocketContext,
            kDefaultMaxSessions, kDefaultSocketName);
}

}  // namespace

int main(int argc, char** argv) {
  std::string socket_name = kDefaultSocketName;
  std::string socket_context = kDefaultSocketContext;
  std::string tcp_spec;
  bool tcp = false;
  bool socket_named = false;
  int max_sessions = kDefaultMaxSessions;
  bool daemonize = false;

  static const option options[] = {
      {"socket", required_argument, nullptr, 's'},
      {"tcp", required_argument, nullptr, 't'},
      {"socket-context", required_argument, nullptr, 'c'},
      {"max-sessions", required_argument, nullptr, 'm'},
      {"daemonize", no_argument, nullptr, 'd'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0},
  };
  for (int opt; (opt = ::getopt_long(argc, argv, "s:t:c:m:dh", options, nullptr)) != -1;) {
    switch (opt) {
      case 's':
        socket_name = optarg;
        socket_named = true;
        break;
      case 't':
        tcp_spec = optarg;
        tcp = true;
        break;
      case 'c':
        socket_context = optarg;
        break;
      case 'm':
        max_sessions = ::atoi(optarg);
        if (max_sessions < 1) {
          KS_LOGE("--max-sessions must be at least 1");
          return 2;
        }
        break;
      case 'd':
        daemonize = true;
        break;
      case 'h':
        Usage(argv[0]);
        return 0;
      default:
        Usage(argv[0]);
        return 2;
    }
  }

  if (tcp && socket_named) {
    KS_LOGE("--socket and --tcp name two different listeners; pick one");
    return 2;
  }

  if (::geteuid() != 0) {
    // Without root there is no setresuid, so every session but one would fail
    // at the handshake. Fail now, where the message is obvious.
    KS_LOGE("must run as root (euid is %u)", ::geteuid());
    return 1;
  }

  // Bound before detaching, so the caller sees any failure and knows the socket
  // is ready the moment the command returns.
  std::string listening_on;
  int listen_fd;
  if (tcp) {
    listen_fd = ListenTcp(tcp_spec, &listening_on);
  } else {
    listen_fd = ListenUnix(socket_name, socket_context);
    listening_on = "abstract socket '" + socket_name + "' (context " +
                   (socket_context.empty() ? "inherited" : socket_context) + ")";
  }
  if (listen_fd < 0) return 1;
  KS_LOGI("listening on %s, up to %d concurrent sessions", listening_on.c_str(), max_sessions);

  if (daemonize && !Daemonize()) {
    KS_LOGE("could not daemonize: %s", ::strerror(errno));
    ::close(listen_fd);
    return 1;
  }

  // Its own process group, so `kill_server` can take down every session with
  // one signal without reaching the adb shell that launched the daemon. After
  // Daemonize, because that forks twice and this must apply to the process that
  // actually runs the accept loop.
  if (::setpgid(0, 0) != 0) {
    KS_LOGE("setpgid: %s -- kill_server would signal the launching shell's "
            "process group, so it is refused",
            ::strerror(errno));
    ::close(listen_fd);
    return 1;
  }

  if (!InstallSignalHandlers()) {
    KS_LOGE("sigaction: %s", ::strerror(errno));
    ::close(listen_fd);
    return 1;
  }

  // Captured before any fork so a child never has to guess: getppid() would
  // return 1 if the supervisor had already died, and signalling init is not an
  // acceptable failure mode.
  const pid_t supervisor_pid = ::getpid();

  int forked = 0;
  while (!g_terminate) {
    const int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0) {
      if (errno == EINTR || errno == ECONNABORTED) continue;
      KS_LOGE("accept: %s", ::strerror(errno));
      break;
    }

    // An interactive exec is a stream of one-keystroke writes, and Nagle would
    // hold each one back waiting for the ack of the last. The client sets this
    // on its end for the same reason.
    if (tcp) {
      const int on = 1;
      ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    }

    // Each session holds a child for its whole lifetime, so the ceiling is what
    // stops a chatty client from fork-bombing the device.
    const int active = forked - static_cast<int>(g_reaped);
    if (active >= max_sessions) {
      KS_LOGE("refusing connection: %d sessions already active", active);
      ::close(fd);
      continue;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
      KS_LOGE("fork: %s", ::strerror(errno));
      ::close(fd);
      continue;
    }
    if (pid == 0) {
      // fork() carries the supervisor's handlers across, and both are wrong
      // here: SIGCHLD reaps children this process does not have, and SIGTERM
      // sets a flag only the accept loop reads -- which would make a session
      // survive the kill_server that was meant to end it. SIGPIPE stays
      // ignored, so a client hanging up mid-response is an EPIPE to handle.
      ::signal(SIGCHLD, SIG_DFL);
      ::signal(SIGTERM, SIG_DFL);

      // The child must not hold the listening socket: it is about to become an
      // untrusted UID, and it would otherwise keep the socket alive after the
      // supervisor exits.
      ::close(listen_fd);
      const int status = keystork::RunConnection(fd, supervisor_pid);
      ::close(fd);
      ::_exit(status);
    }

    forked++;
    ::close(fd);
  }

  ::close(listen_fd);

  if (g_terminate) {
    KS_LOGI("stopping");
    TerminateSessions();
    return 0;
  }
  return 1;
}
