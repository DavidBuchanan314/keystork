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

// Written by the SIGCHLD handler, read by the accept loop.
volatile sig_atomic_t g_reaped = 0;

void HandleSigchld(int /*signo*/) {
  const int saved_errno = errno;
  while (::waitpid(-1, nullptr, WNOHANG) > 0) g_reaped++;
  errno = saved_errno;
}

bool InstallSignalHandlers() {
  struct sigaction sa {};
  sa.sa_handler = HandleSigchld;
  sigemptyset(&sa.sa_mask);
  // SA_RESTART keeps accept() from unwinding every time a session ends.
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  if (::sigaction(SIGCHLD, &sa, nullptr) != 0) return false;

  // A client that hangs up mid-response must give the child an EPIPE to
  // handle, not kill it outright.
  struct sigaction ignore {};
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  return ::sigaction(SIGPIPE, &ignore, nullptr) == 0;
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
int Listen(const std::string& name, const std::string& context) {
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

void Usage(const char* argv0) {
  ::fprintf(stderr,
            "usage: %s [--socket NAME] [--socket-context CONTEXT] [--max-sessions N]\n"
            "\n"
            "  --socket NAME        abstract unix socket to listen on (default: %s)\n"
            "  --socket-context CTX SELinux context to label the socket with, so adbd is\n"
            "                       allowed to connect to it (default: %s). Empty to leave\n"
            "                       the socket in this process's own context.\n"
            "  --max-sessions N     concurrent sessions to allow (default: %d)\n"
            "\n"
            "Run as root. Bridge to a host with:\n"
            "  adb forward tcp:9432 localabstract:%s\n",
            argv0, kDefaultSocketName, kDefaultSocketContext, kDefaultMaxSessions,
            kDefaultSocketName);
}

}  // namespace

int main(int argc, char** argv) {
  std::string socket_name = kDefaultSocketName;
  std::string socket_context = kDefaultSocketContext;
  int max_sessions = kDefaultMaxSessions;

  static const option options[] = {
      {"socket", required_argument, nullptr, 's'},
      {"socket-context", required_argument, nullptr, 'c'},
      {"max-sessions", required_argument, nullptr, 'm'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0},
  };
  for (int opt; (opt = ::getopt_long(argc, argv, "s:c:m:h", options, nullptr)) != -1;) {
    switch (opt) {
      case 's':
        socket_name = optarg;
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
      case 'h':
        Usage(argv[0]);
        return 0;
      default:
        Usage(argv[0]);
        return 2;
    }
  }

  if (::geteuid() != 0) {
    // Without root there is no setresuid, so every session but one would fail
    // at the handshake. Fail now, where the message is obvious.
    KS_LOGE("must run as root (euid is %u)", ::geteuid());
    return 1;
  }

  if (!InstallSignalHandlers()) {
    KS_LOGE("sigaction: %s", ::strerror(errno));
    return 1;
  }

  const int listen_fd = Listen(socket_name, socket_context);
  if (listen_fd < 0) return 1;
  KS_LOGI("listening on abstract socket '%s' (context %s), up to %d concurrent sessions",
          socket_name.c_str(), socket_context.empty() ? "inherited" : socket_context.c_str(),
          max_sessions);

  int forked = 0;
  for (;;) {
    const int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0) {
      if (errno == EINTR || errno == ECONNABORTED) continue;
      KS_LOGE("accept: %s", ::strerror(errno));
      break;
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
      // The child must not hold the listening socket: it is about to become an
      // untrusted UID, and it would otherwise keep the socket alive after the
      // supervisor exits.
      ::close(listen_fd);
      const int status = keystork::RunSession(fd);
      ::close(fd);
      ::_exit(status);
    }

    forked++;
    ::close(fd);
  }

  ::close(listen_fd);
  return 1;
}
