#include "exec.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "framing.h"
#include "log.h"
#include "status.h"

extern char** environ;

namespace keystork {
namespace {

namespace pb = ::keystork::v1;

// One read or write per poll cycle, per fd. Small enough that no single
// direction can monopolize the loop, large enough that a chatty child does not
// cost a syscall per line.
constexpr size_t kChunkBytes = 64 * 1024;

// How much may sit in this process before it stops reading the source. Without
// it, a child writing faster than the client reads (or a client writing faster
// than the child reads) would be buffered here without limit; with it the
// backpressure lands where it belongs -- the pipe fills, or the socket window
// closes.
constexpr size_t kHighWaterBytes = 1024 * 1024;

// waitpid has no descriptor to poll, so once the child's output is finished
// the loop ticks instead of blocking. Only ever reached in the moment between
// the last write and the exit.
constexpr int kReapTickMs = 20;

constexpr unsigned short kDefaultRows = 24;
constexpr unsigned short kDefaultCols = 80;

// A byte stream with a consumed prefix, so draining the front of a queue does
// not copy the rest of it every time.
class ByteQueue {
 public:
  void Append(const void* data, size_t length) {
    Compact();
    buffer_.append(static_cast<const char*>(data), length);
  }

  void Consume(size_t length) {
    head_ += std::min(length, buffer_.size() - head_);
    Compact();
  }

  void Clear() {
    buffer_.clear();
    head_ = 0;
  }

  const char* data() const { return buffer_.data() + head_; }
  size_t size() const { return buffer_.size() - head_; }
  bool empty() const { return size() == 0; }

 private:
  void Compact() {
    if (head_ == buffer_.size()) {
      buffer_.clear();
      head_ = 0;
    } else if (head_ > buffer_.size() / 2) {
      buffer_.erase(0, head_);
      head_ = 0;
    }
  }

  std::string buffer_;
  size_t head_ = 0;
};

// Closes anything still held when it goes out of scope. StartExec has a dozen
// early exits and up to nine descriptors open across them; this is what keeps
// each of those exits to one line.
class Fds {
 public:
  Fds() = default;
  Fds(const Fds&) = delete;
  Fds& operator=(const Fds&) = delete;

  ~Fds() {
    for (const int fd : fds_) {
      if (fd >= 0) ::close(fd);
    }
  }

  int Keep(int fd) {
    fds_.push_back(fd);
    return fd;
  }

  // Hands `fd` to the caller: still open, no longer this object's problem.
  int Release(int fd) {
    for (int& held : fds_) {
      if (held == fd) held = -1;
    }
    return fd;
  }

  void CloseNow(int fd) {
    Release(fd);
    if (fd >= 0) ::close(fd);
  }

 private:
  std::vector<int> fds_;
};

bool SetNonBlocking(int fd) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// The daemon's own environment with the request's entries applied on top,
// replacing rather than duplicating a key that is already there -- execve
// takes the list literally and most programs read only the first match.
bool BuildEnvironment(const pb::ExecRequest& request, std::vector<std::string>* out,
                      std::string* error) {
  if (!request.clear_env()) {
    for (char** entry = ::environ; entry != nullptr && *entry != nullptr; ++entry) {
      out->emplace_back(*entry);
    }
  }

  for (const std::string& entry : request.env()) {
    const size_t equals = entry.find('=');
    if (equals == std::string::npos) {
      *error = "environment entry '" + entry + "' has no '='";
      return false;
    }

    const std::string key = entry.substr(0, equals + 1);
    bool replaced = false;
    for (std::string& existing : *out) {
      if (existing.compare(0, key.size(), key) == 0) {
        existing = entry;
        replaced = true;
        break;
      }
    }
    if (!replaced) out->push_back(entry);
  }
  return true;
}

// Which of the child's setup steps failed. Reported alongside the errno,
// because several of them produce the same one and blaming execve for a
// chdir's ENOENT sends the reader looking at the wrong thing.
enum class Step : int {
  kExecve = 0,
  kSession,
  kTerminal,
  kDescriptors,
  kChdir,
  kGroups,
  kSetgid,
  kSetuid,
};

const char* Describe(Step step) {
  switch (step) {
    case Step::kExecve: return "execve";
    case Step::kSession: return "setsid/setpgid";
    case Step::kTerminal: return "TIOCSCTTY";
    case Step::kDescriptors: return "dup2";
    case Step::kChdir: return "chdir";
    case Step::kGroups: return "setgroups";
    case Step::kSetgid: return "setresgid";
    case Step::kSetuid: return "setresuid";
  }
  return "setup";
}

// What the child writes back on the close-on-exec pipe when it cannot get as
// far as execve. Nothing at all means it did.
struct ChildFailure {
  int step;
  int number;
};

// Everything the child needs, assembled before the fork: after it, this
// process is a single thread in a copy of the parent's heap and allocating is
// best avoided.
struct Plan {
  std::string path;
  std::vector<std::string> argv;
  std::vector<std::string> env;
  std::vector<char*> argv_pointers;
  std::vector<char*> env_pointers;

  bool has_cwd = false;
  std::string cwd;

  bool has_uid = false;
  uid_t uid = 0;
  bool has_gid = false;
  gid_t gid = 0;
  std::vector<gid_t> groups;

  bool pty = false;

  // What becomes the child's 0, 1 and 2. All three are the pty slave when
  // there is one.
  int child_in = -1;
  int child_out = -1;
  int child_err = -1;

  // Write end of the close-on-exec pipe the child reports a failed setup on.
  int error_fd = -1;

  // Captured before the fork, because getppid() in the child would name init
  // if the connection had already died.
  pid_t parent_pid = -1;
};

[[noreturn]] void RunChild(const Plan& plan) {
  const auto fail = [&plan](Step step, int number) {
    // A short write here would look to the parent exactly like a successful
    // exec. Nothing can be done about that from inside the child, and it takes
    // an already-impossible pipe failure to reach.
    const ChildFailure failure = {static_cast<int>(step), number};
    (void)::write(plan.error_fd, &failure, sizeof(failure));
    ::_exit(127);
  };

  // The supervisor ignores SIGPIPE and this child inherited that through two
  // forks. A program that starts life with a signal ignored behaves
  // differently from one that does not -- a shell in a pipeline most of all --
  // so the defaults go back before anything else happens.
  ::signal(SIGPIPE, SIG_DFL);
  ::signal(SIGCHLD, SIG_DFL);
  ::signal(SIGTERM, SIG_DFL);
  sigset_t none;
  ::sigemptyset(&none);
  ::sigprocmask(SIG_SETMASK, &none, nullptr);

  // Its own process group either way: that is what lets a signal reach the
  // whole job, and what keeps kill_server's kill(0, SIGTERM) -- which walks
  // the daemon's group -- from reaching a child that is not part of the
  // daemon. A controlling terminal belongs to a session, so a pty needs the
  // stronger form.
  if (plan.pty) {
    if (::setsid() < 0) fail(Step::kSession, errno);
  } else if (::setpgid(0, 0) != 0) {
    fail(Step::kSession, errno);
  }

  // Now that this child is out of the daemon's process group, nothing else
  // would notice its connection ending. PDEATHSIG survives execve as long as
  // the new program is not set-uid, which nothing here is.
  ::prctl(PR_SET_PDEATHSIG, SIGKILL);
  if (::getppid() != plan.parent_pid) ::_exit(128 + SIGKILL);

  // Must come after setsid and before the descriptor shuffle: it is the open
  // slave that becomes the terminal.
  if (plan.pty && ::ioctl(plan.child_in, TIOCSCTTY, 0) != 0) fail(Step::kTerminal, errno);

  if (::dup2(plan.child_in, STDIN_FILENO) < 0) fail(Step::kDescriptors, errno);
  if (::dup2(plan.child_out, STDOUT_FILENO) < 0) fail(Step::kDescriptors, errno);
  if (::dup2(plan.child_err, STDERR_FILENO) < 0) fail(Step::kDescriptors, errno);
  // The originals are close-on-exec, so the program sees exactly 0, 1 and 2 --
  // dup2 is what clears the flag on the copies.

  if (plan.has_cwd && ::chdir(plan.cwd.c_str()) != 0) fail(Step::kChdir, errno);

  // Groups first, then GID, then UID: each of the three needs the privilege
  // the next one gives up.
  if (plan.has_uid || plan.has_gid) {
    const gid_t gid = plan.has_gid ? plan.gid : static_cast<gid_t>(plan.uid);
    if (plan.groups.empty()) {
      if (::setgroups(1, &gid) != 0) fail(Step::kGroups, errno);
    } else if (::setgroups(plan.groups.size(), plan.groups.data()) != 0) {
      fail(Step::kGroups, errno);
    }
    if (::setresgid(gid, gid, gid) != 0) fail(Step::kSetgid, errno);
  }
  if (plan.has_uid && ::setresuid(plan.uid, plan.uid, plan.uid) != 0) fail(Step::kSetuid, errno);

  ::execve(plan.path.c_str(), plan.argv_pointers.data(), plan.env_pointers.data());
  fail(Step::kExecve, errno);
  ::_exit(127);
}

}  // namespace

bool StartExec(const pb::ExecRequest& request, ExecProcess* process, pb::Error* error) {
  if (request.path().empty()) {
    FillProtocolError("exec needs a path", error);
    return false;
  }

  Plan plan;
  plan.path = request.path();
  if (request.argv().empty()) {
    // argv[0] is not optional to execve, and a program that finds it empty
    // behaves oddly rather than failing, so the default is the conventional
    // one rather than nothing.
    plan.argv.push_back(plan.path);
  } else {
    plan.argv.assign(request.argv().begin(), request.argv().end());
  }

  std::string environment_error;
  if (!BuildEnvironment(request, &plan.env, &environment_error)) {
    FillProtocolError(environment_error, error);
    return false;
  }

  plan.argv_pointers.reserve(plan.argv.size() + 1);
  for (std::string& entry : plan.argv) plan.argv_pointers.push_back(entry.data());
  plan.argv_pointers.push_back(nullptr);
  plan.env_pointers.reserve(plan.env.size() + 1);
  for (std::string& entry : plan.env) plan.env_pointers.push_back(entry.data());
  plan.env_pointers.push_back(nullptr);

  plan.has_cwd = request.has_cwd();
  if (plan.has_cwd) plan.cwd = request.cwd();
  plan.has_uid = request.has_uid();
  plan.uid = static_cast<uid_t>(request.uid());
  plan.has_gid = request.has_gid();
  plan.gid = static_cast<gid_t>(request.gid());
  for (const uint32_t group : request.groups()) plan.groups.push_back(static_cast<gid_t>(group));
  plan.pty = request.has_pty();
  plan.parent_pid = ::getpid();

  Fds fds;
  const auto fail = [&](const char* what) {
    FillIdentityError(std::string(what) + " failed: " + ::strerror(errno), errno, error);
    return false;
  };

  int master = -1;
  int slave = -1;
  int child_stdin = -1;
  int child_stdout = -1;
  int child_stderr = -1;
  int parent_stdin = -1;
  int parent_stdout = -1;
  int parent_stderr = -1;

  if (plan.pty) {
    winsize size{};
    size.ws_row = request.pty().rows() != 0 ? static_cast<unsigned short>(request.pty().rows())
                                            : kDefaultRows;
    size.ws_col = request.pty().cols() != 0 ? static_cast<unsigned short>(request.pty().cols())
                                            : kDefaultCols;
    if (::openpty(&master, &slave, nullptr, nullptr, &size) != 0) return fail("openpty");
    fds.Keep(master);
    fds.Keep(slave);

    // openpty hands back plain descriptors. Without this the slave would
    // survive execve as a fourth copy of the child's own terminal, and the
    // master would leak into it outright.
    ::fcntl(master, F_SETFD, FD_CLOEXEC);
    ::fcntl(slave, F_SETFD, FD_CLOEXEC);

    // The child keeps the slave open across the UID drop, so it does not need
    // this to use its terminal -- but reopening /dev/tty, and anything that
    // stats the tty, checks the device's own ownership.
    if (plan.has_uid) {
      ::fchown(slave, plan.uid, plan.has_gid ? plan.gid : static_cast<gid_t>(plan.uid));
    }

    child_stdin = child_stdout = child_stderr = slave;
  } else {
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (::pipe2(in_pipe, O_CLOEXEC) != 0) return fail("pipe2");
    fds.Keep(in_pipe[0]);
    fds.Keep(in_pipe[1]);
    if (::pipe2(out_pipe, O_CLOEXEC) != 0) return fail("pipe2");
    fds.Keep(out_pipe[0]);
    fds.Keep(out_pipe[1]);
    if (::pipe2(err_pipe, O_CLOEXEC) != 0) return fail("pipe2");
    fds.Keep(err_pipe[0]);
    fds.Keep(err_pipe[1]);

    child_stdin = in_pipe[0];
    child_stdout = out_pipe[1];
    child_stderr = err_pipe[1];
    parent_stdin = in_pipe[1];
    parent_stdout = out_pipe[0];
    parent_stderr = err_pipe[0];
  }

  int error_pipe[2] = {-1, -1};
  if (::pipe2(error_pipe, O_CLOEXEC) != 0) return fail("pipe2");
  fds.Keep(error_pipe[0]);
  fds.Keep(error_pipe[1]);

  plan.child_in = child_stdin;
  plan.child_out = child_stdout;
  plan.child_err = child_stderr;
  plan.error_fd = error_pipe[1];

  const pid_t pid = ::fork();
  if (pid < 0) return fail("fork");
  if (pid == 0) RunChild(plan);

  // The child's ends are the child's now. The error pipe's write end most of
  // all: while this process holds a copy, the read below would never see the
  // EOF that means the execve went through.
  fds.CloseNow(error_pipe[1]);
  if (plan.pty) {
    fds.CloseNow(slave);
  } else {
    fds.CloseNow(child_stdin);
    fds.CloseNow(child_stdout);
    fds.CloseNow(child_stderr);
  }

  ChildFailure failure = {};
  ssize_t got;
  while ((got = ::read(error_pipe[0], &failure, sizeof(failure))) < 0 && errno == EINTR) {
  }
  fds.CloseNow(error_pipe[0]);

  if (got == static_cast<ssize_t>(sizeof(failure))) {
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    const auto step = static_cast<Step>(failure.step);
    std::string detail = "could not exec '" + plan.path + "': ";
    if (step != Step::kExecve) detail += std::string(Describe(step)) + " failed: ";
    FillIdentityError(detail + ::strerror(failure.number), failure.number, error);
    return false;
  }

  process->pid = pid;
  process->pty = plan.pty;
  if (plan.pty) {
    // One device, two directions. A dup lets the pump treat them as it treats
    // a pair of pipes -- close one, keep the other -- instead of special-
    // casing a descriptor that is both at once.
    const int write_side = ::fcntl(master, F_DUPFD_CLOEXEC, 0);
    if (write_side < 0) {
      const bool failed = fail("dup");
      ::kill(pid, SIGKILL);
      while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
      }
      return failed;
    }
    process->out = fds.Release(master);
    process->in = write_side;
    process->err = -1;
  } else {
    process->in = fds.Release(parent_stdin);
    process->out = fds.Release(parent_stdout);
    process->err = fds.Release(parent_stderr);
  }

  SetNonBlocking(process->in);
  SetNonBlocking(process->out);
  if (process->err >= 0) SetNonBlocking(process->err);

  KS_LOGI("exec pid=%d %s%s", pid, plan.path.c_str(), plan.pty ? " (pty)" : "");
  return true;
}

int RunExecSession(int fd, ExecProcess* process) {
  if (!SetNonBlocking(fd)) {
    KS_LOGE("could not make the connection non-blocking: %s", ::strerror(errno));
  }

  FrameBuffer incoming;
  ByteQueue to_client;
  ByteQueue to_child;
  std::vector<char> buffer(kChunkBytes);

  bool stdin_eof = false;
  bool client_gone = false;
  bool reaped = false;

  const auto enqueue = [&to_client](const pb::ExecEvent& event) {
    std::string encoded;
    if (!event.SerializeToString(&encoded)) {
      KS_LOGE("failed to serialize an exec event");
      return;
    }
    uint8_t header[4];
    EncodeFrameHeader(static_cast<uint32_t>(encoded.size()), header);
    to_client.Append(header, sizeof(header));
    to_client.Append(encoded.data(), encoded.size());
  };

  const auto drain = [&](int* source, pb::ExecOutput_Stream stream) {
    const ssize_t got = ::read(*source, buffer.data(), buffer.size());
    if (got > 0) {
      pb::ExecEvent event;
      auto* output = event.mutable_output();
      output->set_stream(stream);
      output->set_data(buffer.data(), static_cast<size_t>(got));
      enqueue(event);
      return;
    }
    if (got < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return;
    // Zero is the pipe's last writer closing. EIO is that same event on a pty
    // master: once the slave side is gone Linux reports an error, not an EOF.
    ::close(*source);
    *source = -1;
  };

  while (!client_gone) {
    const bool output_done = process->out < 0 && process->err < 0;

    if (output_done && !reaped) {
      int status = 0;
      const pid_t done = ::waitpid(process->pid, &status, WNOHANG);
      if (done == process->pid || (done < 0 && errno != EINTR)) {
        reaped = true;
        pb::ExecEvent event;
        auto* exit = event.mutable_exit();
        if (done == process->pid && WIFSIGNALED(status)) {
          exit->set_term_signal(static_cast<uint32_t>(WTERMSIG(status)));
        } else {
          exit->set_exit_code(static_cast<uint32_t>(
              done == process->pid && WIFEXITED(status) ? WEXITSTATUS(status) : 0));
        }
        enqueue(event);
      }
    }
    // The exit event is the last thing on the wire, so the loop ends only once
    // it has actually been written.
    if (reaped && to_client.empty()) break;

    // Deferred from whenever the request arrived until the queue behind it has
    // actually drained -- closing on the request itself would throw away
    // stdin that was still in flight. It has to happen here, before the poll:
    // a child waiting on this EOF produces nothing to wake the loop with, so
    // deciding it after the poll would be deciding it never.
    if (stdin_eof && to_child.empty() && process->in >= 0 && !process->pty) {
      ::close(process->in);
      process->in = -1;
    }

    pollfd fds[4];
    int count = 0;
    int socket_index = -1;
    int stdin_index = -1;
    int stdout_index = -1;
    int stderr_index = -1;

    socket_index = count;
    fds[count].fd = fd;
    fds[count].events = 0;
    fds[count].revents = 0;
    // Stop taking input while the child is behind on what it already has;
    // otherwise a client that writes faster than the child reads is buffered
    // here rather than being made to wait.
    if (to_child.size() < kHighWaterBytes) fds[count].events |= POLLIN;
    if (!to_client.empty()) fds[count].events |= POLLOUT;
    count++;

    if (process->in >= 0 && !to_child.empty()) {
      stdin_index = count;
      fds[count].fd = process->in;
      fds[count].events = POLLOUT;
      fds[count].revents = 0;
      count++;
    }

    // The mirror of the rule above: let the child's pipe fill rather than grow
    // this queue without bound when the client is not draining it.
    const bool may_read_child = to_client.size() < kHighWaterBytes;
    if (process->out >= 0 && may_read_child) {
      stdout_index = count;
      fds[count].fd = process->out;
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      count++;
    }
    if (process->err >= 0 && may_read_child) {
      stderr_index = count;
      fds[count].fd = process->err;
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      count++;
    }

    const int timeout = (output_done && !reaped) ? kReapTickMs : -1;
    if (::poll(fds, count, timeout) < 0) {
      if (errno == EINTR) continue;
      KS_LOGE("poll: %s", ::strerror(errno));
      break;
    }

    if (stdout_index >= 0 && fds[stdout_index].revents != 0) {
      drain(&process->out, pb::ExecOutput::STREAM_STDOUT);
    }
    if (stderr_index >= 0 && fds[stderr_index].revents != 0) {
      drain(&process->err, pb::ExecOutput::STREAM_STDERR);
    }

    if (stdin_index >= 0 && fds[stdin_index].revents != 0) {
      const size_t want = std::min(to_child.size(), kChunkBytes);
      const ssize_t put = ::write(process->in, to_child.data(), want);
      if (put > 0) {
        to_child.Consume(static_cast<size_t>(put));
      } else if (put < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
        // The child closed its stdin, or died. SIGPIPE is ignored in this
        // process, so that arrives as an EPIPE to notice rather than a death.
        ::close(process->in);
        process->in = -1;
        to_child.Clear();
      }
    }

    if (!to_client.empty() && (fds[socket_index].revents & POLLOUT) != 0) {
      const size_t want = std::min(to_client.size(), kChunkBytes);
      const ssize_t put = ::write(fd, to_client.data(), want);
      if (put > 0) {
        to_client.Consume(static_cast<size_t>(put));
      } else if (put < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
        client_gone = true;
      }
    }

    if ((fds[socket_index].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0) continue;

    const ssize_t got = ::read(fd, buffer.data(), buffer.size());
    if (got > 0) {
      incoming.Append(buffer.data(), static_cast<size_t>(got));
    } else if (got == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
      client_gone = true;
    }

    std::string frame;
    while (incoming.Next(&frame)) {
      pb::ExecInput input;
      if (!input.ParseFromString(frame)) {
        KS_LOGE("malformed exec input");
        client_gone = true;
        break;
      }
      switch (input.body_case()) {
        case pb::ExecInput::kStdinData:
          if (process->in >= 0 && !stdin_eof) {
            to_child.Append(input.stdin_data().data(), input.stdin_data().size());
          }
          break;
        case pb::ExecInput::kStdinEof:
          stdin_eof = true;
          // A pty master has nothing to close -- it stays open in both
          // directions for as long as this process holds it -- so "no more
          // input" is expressed the way a terminal expresses it.
          if (process->pty && process->in >= 0) to_child.Append("\004", 1);
          break;
        case pb::ExecInput::kResize: {
          const int terminal = process->out >= 0 ? process->out : process->in;
          if (process->pty && terminal >= 0) {
            winsize size{};
            size.ws_row = static_cast<unsigned short>(input.resize().rows());
            size.ws_col = static_cast<unsigned short>(input.resize().cols());
            ::ioctl(terminal, TIOCSWINSZ, &size);
          }
          break;
        }
        case pb::ExecInput::kSignal:
          // The whole group: the child was given one of its own precisely so
          // that a signal reaches what it started, not just the shell in
          // front of it.
          ::kill(-process->pid, static_cast<int>(input.signal()));
          break;
        case pb::ExecInput::BODY_NOT_SET:
          break;
      }
    }
    if (incoming.over_limit()) {
      KS_LOGE("client announced an exec frame past the size limit");
      client_gone = true;
    }
  }

  if (process->in >= 0) ::close(process->in);
  if (process->out >= 0) ::close(process->out);
  if (process->err >= 0) ::close(process->err);
  process->in = process->out = process->err = -1;

  if (!reaped) {
    // Nothing is left to read this child's output or answer its input, and it
    // has no other parent to be reaped by. The group, so that anything it
    // started goes with it.
    ::kill(-process->pid, SIGKILL);
    while (::waitpid(process->pid, nullptr, 0) < 0 && errno == EINTR) {
    }
    KS_LOGI("exec pid=%d killed: the client disconnected", process->pid);
  }
  return 0;
}

}  // namespace keystork
