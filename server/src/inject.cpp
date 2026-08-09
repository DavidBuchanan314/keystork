#include "inject.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <android/dlext.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "status.h"
#include "tracee.h"

// The agent, put here by cmake/embed_agent.cmake.
extern "C" const char kKeystorkAgentStart[];
extern "C" const char kKeystorkAgentEnd[];

namespace keystork {
namespace {

namespace pb = ::keystork::v1;

// AMS gives a starting process ten seconds to call attachApplication before it
// declares the start timed out, so everything from the fork to the injection
// has to fit inside that. This is the outer bound on waiting for the fork to
// happen at all.
constexpr int kDefaultTimeoutMs = 15000;

// A child that has run this many syscalls without dropping its UID is not an
// app being specialized. Bounds the damage from a wrong guess about where the
// landmark is -- and the damage is somebody else's: every child the zygote
// forks while we are seized gets stepped, so this is how long an unrelated
// app's launch can be held up. The target's setresuid arrives within a few
// hundred, so there is no reason for it to be generous.
constexpr int kMaxStepsPerChild = 4000;

// <linux/memfd.h>, which the NDK does not ship.
constexpr unsigned kMfdCloexec = 0x0001;
constexpr unsigned kMfdExec = 0x0010;

// Syscall stops are SIGTRAP|0x80 once PTRACE_O_TRACESYSGOOD is on, which is
// what tells them apart from a real SIGTRAP.
constexpr int kSyscallTrap = SIGTRAP | 0x80;

int64_t NowMs() {
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  return static_cast<int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

volatile sig_atomic_t g_deadline_passed = 0;
void OnAlarm(int /*signo*/) { g_deadline_passed = 1; }

// fork+exec with stdio on /dev/null, since none of these helpers has anything
// to say to the connection.
pid_t Spawn(const std::vector<std::string>& argv) {
  std::vector<char*> raw;
  raw.reserve(argv.size() + 1);
  for (const std::string& word : argv) raw.push_back(const_cast<char*>(word.c_str()));
  raw.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    ::signal(SIGPIPE, SIG_DFL);
    const int null_fd = ::open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
      ::dup2(null_fd, STDIN_FILENO);
      ::dup2(null_fd, STDOUT_FILENO);
      ::dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) ::close(null_fd);
    }
    ::execv(raw[0], raw.data());
    ::_exit(127);
  }
  return pid;
}

void SpawnAndWait(const std::vector<std::string>& argv) {
  const pid_t pid = Spawn(argv);
  if (pid < 0) return;
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

// Runs a helper and hands back what it printed. Same shape as SpawnAndWait,
// with stdout on a pipe -- the one thing here whose *output* matters.
std::string SpawnAndRead(const std::vector<std::string>& argv) {
  int pipes[2] = {-1, -1};
  if (::pipe2(pipes, O_CLOEXEC) != 0) return "";

  std::vector<char*> raw;
  raw.reserve(argv.size() + 1);
  for (const std::string& word : argv) raw.push_back(const_cast<char*>(word.c_str()));
  raw.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(pipes[0]);
    ::close(pipes[1]);
    return "";
  }
  if (pid == 0) {
    ::signal(SIGPIPE, SIG_DFL);
    const int null_fd = ::open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
      ::dup2(null_fd, STDIN_FILENO);
      ::dup2(null_fd, STDERR_FILENO);
      if (null_fd > STDERR_FILENO) ::close(null_fd);
    }
    ::dup2(pipes[1], STDOUT_FILENO);
    ::execv(raw[0], raw.data());
    ::_exit(127);
  }

  ::close(pipes[1]);
  std::string output;
  char chunk[512];
  for (;;) {
    const ssize_t got = ::read(pipes[0], chunk, sizeof(chunk));
    if (got > 0) {
      output.append(chunk, static_cast<size_t>(got));
      continue;
    }
    if (got < 0 && errno == EINTR) continue;
    break;
  }
  ::close(pipes[0]);

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  return output;
}

// What `am start` would launch for a package: the flattened
// "package/class" the package manager resolves the launcher intent to.
//
// Resolved here rather than inside the shell line that starts it, because the
// class half is needed twice over -- `am` wants it, and so does the agent,
// which has to answer for that name once the app's own classes are gone.
bool ResolveLaunchActivity(const std::string& package, std::string* component,
                           std::string* activity_class, std::string* error) {
  const std::string said =
      SpawnAndRead({"/system/bin/cmd", "package", "resolve-activity", "--brief", package});

  // Two lines on a hit, the flattened component last; a miss says so in prose,
  // which has no '/' in it and falls out below.
  std::string last;
  size_t at = 0;
  while (at < said.size()) {
    const size_t end = said.find('\n', at);
    const std::string line = said.substr(at, end == std::string::npos ? end : end - at);
    if (!line.empty()) last = line;
    if (end == std::string::npos) break;
    at = end + 1;
  }

  const size_t slash = last.find('/');
  if (slash == std::string::npos || slash + 1 >= last.size()) {
    *error = "no launchable activity for " + package + " (resolve-activity said \"" + last + "\")";
    return false;
  }

  *component = last;
  *activity_class = last.substr(slash + 1);
  // The manifest form: a leading dot means the package's own namespace, and
  // the class the framework will ask for is the expanded one.
  if ((*activity_class)[0] == '.') *activity_class = last.substr(0, slash) + *activity_class;
  return true;
}

// The 64-bit zygote, by name. Not webview_zygote, which is a separate pool
// that forks its own thing, and not the 32-bit one, which is out of scope.
pid_t FindZygote() {
  DIR* proc = ::opendir("/proc");
  if (proc == nullptr) return -1;

  pid_t found = -1;
  for (dirent* entry = ::readdir(proc); entry != nullptr && found < 0; entry = ::readdir(proc)) {
    const pid_t pid = ::atoi(entry->d_name);
    if (pid <= 0) continue;

    char path[64];
    ::snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) continue;
    char cmdline[64] = {0};
    const ssize_t got = ::read(fd, cmdline, sizeof(cmdline) - 1);
    ::close(fd);
    if (got <= 0) continue;
    // cmdline is NUL-separated; argv[0] is all we want.
    if (::strcmp(cmdline, "zygote64") == 0) found = pid;
  }
  ::closedir(proc);
  return found;
}

// An entry point in the target, and what to tell the linker the caller was.
struct Entry {
  uint64_t function = 0;
  uint64_t caller = 0;
  bool takes_caller = false;
  std::string symbol;
};

struct Candidate {
  const char* symbol;
  bool takes_caller;
};

// Turns a symbol resolved in this process into the same symbol in `pid`, by
// finding which file it came out of and where that file sits over there.
bool Relocate(pid_t pid, void* local_symbol, uint64_t* remote, std::string* module) {
  const auto address = reinterpret_cast<uint64_t>(local_symbol);
  uint64_t local_base = 0;
  if (!FindModuleForAddress(::getpid(), address, module, &local_base)) return false;
  uint64_t remote_base = 0;
  if (!FindModuleBase(pid, module->c_str(), &remote_base)) return false;
  *remote = address - local_base + remote_base;
  return true;
}

// The linker decides which namespace a dlopen or dlsym runs in from the
// *caller's* address, and a call driven by ptrace has no caller -- our LR
// points at a PROT_NONE trap page. The __loader_ forms exist precisely so the
// caller can be stated outright, so they are the ones to want. Falling back to
// the public entry point means whatever the linker infers from that trap
// address, which may or may not be the namespace the library needs.
bool ResolveEntry(pid_t pid, const Candidate* candidates, size_t count, Entry* out,
                  std::string* error) {
  for (size_t i = 0; i < count; i++) {
    void* local = ::dlsym(RTLD_DEFAULT, candidates[i].symbol);
    if (local == nullptr) continue;

    std::string module;
    uint64_t remote = 0;
    if (!Relocate(pid, local, &remote, &module)) continue;

    out->function = remote;
    out->takes_caller = candidates[i].takes_caller;
    out->symbol = candidates[i].symbol;

    // Any address inside a real library will do: the linker only uses it to
    // find the soinfo that owns it, and libc is in the default namespace,
    // which is all there is this early.
    if (out->takes_caller && !FindModuleBase(pid, "/libc.so", &out->caller)) {
      out->takes_caller = false;
    }
    KS_LOGI("%s from %s at %#llx (caller %#llx)", candidates[i].symbol, module.c_str(),
            static_cast<unsigned long long>(out->function),
            static_cast<unsigned long long>(out->caller));
    return true;
  }
  *error = std::string("could not resolve ") + candidates[0].symbol + " or its fallbacks";
  return false;
}

constexpr Candidate kDlopenExt[] = {{"__loader_android_dlopen_ext", true},
                                    {"android_dlopen_ext", false}};
constexpr Candidate kDlsym[] = {{"__loader_dlsym", true}, {"dlsym", false}};

// Asks the target what went wrong, since dlerror's message lives over there.
std::string RemoteDlerror(pid_t pid, Tracee* tracee, Borrow* borrow) {
  void* local = ::dlsym(RTLD_DEFAULT, "dlerror");
  if (local == nullptr) return "";
  std::string module;
  uint64_t remote = 0;
  if (!Relocate(pid, local, &remote, &module)) return "";

  const CallResult call = borrow->Call(remote);
  if (!call.returned() || call.value == 0) return "";

  char message[256] = {0};
  // Short of the end of the mapping is fine; a partial read of a string is
  // still the start of the string.
  for (size_t length = sizeof(message) - 1; length > 0; length /= 2) {
    if (tracee->ReadMemory(call.value, message, length)) break;
    message[0] = '\0';
  }
  message[sizeof(message) - 1] = '\0';
  return message;
}

// Scratch layout. One page is ample and keeps this to a single mapping.
constexpr uint64_t kMemfdNameAt = 0;
constexpr uint64_t kLibraryNameAt = 64;
constexpr uint64_t kExtInfoAt = 256;

bool InjectAgent(pid_t pid, uint64_t* handle, std::string* error) {
  const auto agent_size = static_cast<size_t>(kKeystorkAgentEnd - kKeystorkAgentStart);
  KS_LOGI("injecting the %zu-byte agent into %d", agent_size, pid);

  Tracee tracee(pid);
  Borrow borrow(&tracee);

  const auto page = static_cast<size_t>(::getpagesize());
  const int64_t scratch = borrow.Syscall(SYS_mmap, 0, page, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, static_cast<uint64_t>(-1), 0);
  if (SyscallFailed(scratch)) {
    *error = std::string("could not map scratch in the target: ") +
             ::strerror(static_cast<int>(-scratch));
    return false;
  }

  static const char kMemfdName[] = "keystork-agent";
  static const char kLibraryName[] = "libkeystork-agent.so";
  tracee.WriteMemory(scratch + kMemfdNameAt, kMemfdName, sizeof(kMemfdName));
  tracee.WriteMemory(scratch + kLibraryNameAt, kLibraryName, sizeof(kLibraryName));

  // MFD_EXEC matters from 6.3 on: without it the memfd may be born with the
  // noexec seal, depending on vm.memfd_noexec, and the linker's PROT_EXEC
  // mapping of the text segment would then be refused. Older kernels have
  // never heard of the flag and reject it outright.
  int64_t fd = borrow.Syscall(SYS_memfd_create, scratch + kMemfdNameAt, kMfdCloexec | kMfdExec);
  if (SyscallFailed(fd)) {
    KS_LOGI("memfd_create with MFD_EXEC failed (%s); this kernel predates it",
            ::strerror(static_cast<int>(-fd)));
    fd = borrow.Syscall(SYS_memfd_create, scratch + kMemfdNameAt, kMfdCloexec);
  }
  if (SyscallFailed(fd)) {
    *error = std::string("memfd_create failed in the target: ") +
             ::strerror(static_cast<int>(-fd));
    return false;
  }

  // Mapping a zero-length memfd only faults, so it has to be sized first.
  const int64_t sized = borrow.Syscall(SYS_ftruncate, fd, agent_size);
  if (SyscallFailed(sized)) {
    *error = std::string("ftruncate failed in the target: ") + ::strerror(static_cast<int>(-sized));
    return false;
  }

  // A window onto the memfd purely to fill it: MAP_SHARED, so a single
  // process_vm_writev of the whole library writes through to the file. The
  // linker maps its own segments afterwards, with the permissions it wants.
  const int64_t window = borrow.Syscall(SYS_mmap, 0, agent_size, PROT_READ | PROT_WRITE,
                                        MAP_SHARED, static_cast<uint64_t>(fd), 0);
  if (SyscallFailed(window)) {
    *error = std::string("could not map the memfd in the target: ") +
             ::strerror(static_cast<int>(-window));
    return false;
  }
  if (!tracee.WriteMemory(window, kKeystorkAgentStart, agent_size)) {
    *error = tracee.error();
    return false;
  }
  borrow.Syscall(SYS_munmap, window, agent_size);

  android_dlextinfo extinfo{};
  extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
  extinfo.library_fd = static_cast<int>(fd);
  tracee.WriteMemory(scratch + kExtInfoAt, &extinfo, sizeof(extinfo));

  Entry loader;
  if (!ResolveEntry(pid, kDlopenExt, std::size(kDlopenExt), &loader, error)) return false;

  if (!tracee.ok()) {
    *error = tracee.error();
    return false;
  }

  const CallResult call =
      loader.takes_caller
          ? borrow.Call(loader.function, scratch + kLibraryNameAt, RTLD_NOW, scratch + kExtInfoAt,
                        loader.caller)
          : borrow.Call(loader.function, scratch + kLibraryNameAt, RTLD_NOW, scratch + kExtInfoAt);
  KS_LOGI("%s -> %s", loader.symbol.c_str(), Describe(call).c_str());

  // Every outcome but a returning dlopen is now a failure. That is a change:
  // the agent used to _exit from its constructor to prove it had run, which
  // made EXITED an ordinary result. It returns instead, and a process that
  // died inside dlopen is a process there is no session to have with.
  if (!call.returned()) {
    *error = "dlopen of the agent " + Describe(call);
    if (call.outcome == CallResult::Outcome::kFailed && !tracee.ok()) *error = tracee.error();
    return false;
  }
  if (call.value == 0) {
    const std::string reason = RemoteDlerror(pid, &tracee, &borrow);
    *error = "the linker refused the agent: " + (reason.empty() ? "(no dlerror)" : reason);
    return false;
  }

  // The linker has mapped what it needs, so the descriptor can go. The scratch
  // page deliberately stays: the library name lived in it, and bionic is
  // believed to copy that rather than retain the pointer, but being wrong
  // would mean the app crashing on some later dl_iterate_phdr rather than
  // here. One page is not worth that.
  borrow.Syscall(SYS_close, fd);
  *handle = call.value;
  return true;
}

// ioctl(_, BINDER_SET_MAX_THREADS) -- _IOW('b', 5, __u32). ProcessState's
// constructor issues this from open_driver(), reached from
// AppRuntime::onZygoteInit via ZygoteInit.nativeZygoteInit. That places it
// after postForkChild -- so ART has done DidForkFromZygote and has its daemon
// threads -- and before RuntimeInit.applicationInit, which is what produces
// the Runnable that invokes ActivityThread.main. The zygote itself never
// builds a ProcessState, so the child's really is the first.
constexpr uint64_t kBinderSetMaxThreads = 0x40046205;

// What a landmark looks like from a syscall-*entry* stop: the registers are
// the tracee's own, and the Tracee is there for reading whatever they point
// at. True means "this is the syscall we were waiting for", and stepping then
// stops at its exit.
using Landmark = std::function<bool(Tracee&, const user_regs_struct&)>;

// The simple kind: a syscall number and one register.
Landmark SyscallArgumentIs(long number, int index, uint64_t value) {
  return [number, index, value](Tracee&, const user_regs_struct& registers) {
    return static_cast<long>(registers.regs[8]) == number && registers.regs[index] == value;
  };
}

// The main looper polling. MessageQueue.next() calls nativePollOnce before it
// dequeues anything, so a stop at the exit of one of these is a moment when a
// message that has arrived is on the queue and has not been dispatched --
// which is the whole window stage three needs.
//
// bionic's epoll_wait is epoll_pwait on aarch64; epoll_pwait2 is matched too
// so that a libc which switches does not silently stop matching.
Landmark IsLooperPoll() {
  return [](Tracee&, const user_regs_struct& registers) {
    const long number = static_cast<long>(registers.regs[8]);
    return number == SYS_epoll_pwait
#ifdef SYS_epoll_pwait2
           || number == SYS_epoll_pwait2
#endif
        ;
  };
}

// Runs the target forward until it is stopped at the *exit* of the first
// syscall the landmark claims -- an exit stop being somewhere safe to borrow
// the thread from.
//
// Signals are forwarded rather than swallowed: ART uses SIGSEGV for its
// implicit null and stack-overflow checks, so eating one during startup would
// kill the process outright.
bool StepToSyscallExit(pid_t pid, const Landmark& landmark, int64_t deadline, int* steps,
                       std::string* error) {
  Tracee looking(pid);
  bool at_entry = true;
  bool claiming = false;
  int pending = 0;
  *steps = 0;

  for (;;) {
    if (NowMs() > deadline || g_deadline_passed) {
      *error = "gave up after " + std::to_string(*steps) + " syscalls waiting for the runtime";
      return false;
    }
    if (::ptrace(PTRACE_SYSCALL, pid, nullptr,
                 reinterpret_cast<void*>(static_cast<long>(pending))) != 0) {
      *error = std::string("could not step ") + std::to_string(pid) + ": " + ::strerror(errno);
      return false;
    }
    pending = 0;

    int status = 0;
    if (::waitpid(pid, &status, __WALL) < 0) {
      if (errno == EINTR) continue;
      *error = std::string("waitpid failed while stepping: ") + ::strerror(errno);
      return false;
    }
    if (!WIFSTOPPED(status)) {
      *error = "the target exited while stepping to the runtime landmark";
      return false;
    }

    const int signal = WSTOPSIG(status);
    if (signal != kSyscallTrap) {
      pending = (signal == SIGTRAP || signal == SIGSTOP) ? 0 : signal;
      continue;
    }
    if (claiming) return true;

    if (at_entry) {
      user_regs_struct registers{};
      if (looking.ReadRegisters(&registers) && landmark(looking, registers)) claiming = true;
    }
    at_entry = !at_entry;
    (*steps)++;
  }
}

// An entry point of the agent's, resolved through the target's own dlsym on
// the handle dlopen gave back -- cheaper and more certain than working out
// what a memfd mapping ended up being called.
//
// Done once per symbol and kept, because the calls that follow happen with the
// target stopped at places we have stepped it to, and resolving there would
// mean a scratch mapping at each one.
bool RemoteSymbol(pid_t pid, uint64_t handle, const char* symbol, uint64_t* address,
                  std::string* error) {
  Tracee tracee(pid);
  Borrow borrow(&tracee);

  const auto page = static_cast<size_t>(::getpagesize());
  const int64_t scratch = borrow.Syscall(SYS_mmap, 0, page, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, static_cast<uint64_t>(-1), 0);
  if (SyscallFailed(scratch)) {
    *error = std::string("could not map scratch to resolve ") + symbol + ": " +
             ::strerror(static_cast<int>(-scratch));
    return false;
  }

  if (!tracee.WriteMemory(scratch, symbol, ::strlen(symbol) + 1)) {
    *error = tracee.error();
    return false;
  }

  Entry dlsym_entry;
  if (!ResolveEntry(pid, kDlsym, std::size(kDlsym), &dlsym_entry, error)) return false;

  const CallResult found =
      dlsym_entry.takes_caller
          ? borrow.Call(dlsym_entry.function, handle, scratch, dlsym_entry.caller)
          : borrow.Call(dlsym_entry.function, handle, scratch);
  borrow.Syscall(SYS_munmap, static_cast<uint64_t>(scratch), page);

  if (!found.returned() || found.value == 0) {
    *error = std::string("dlsym(") + symbol + ") in the target " + Describe(found);
    return false;
  }
  KS_LOGI("%s at %#llx", symbol, static_cast<unsigned long long>(found.value));
  *address = found.value;
  return tracee.ok() ? true : (*error = tracee.error(), false);
}

// Calls one of the agent's entry points in the stopped target and hands back
// what it returned.
bool CallAgent(pid_t pid, uint64_t function, const char* symbol, uint64_t first, uint64_t second,
               int* agent_result, std::string* error) {
  Tracee tracee(pid);
  Borrow borrow(&tracee);

  const CallResult called = borrow.Call(function, first, second);
  if (!called.returned()) {
    *error = std::string(symbol) + " " + Describe(called);
    return false;
  }
  *agent_result = static_cast<int>(static_cast<int32_t>(called.value));
  return tracee.ok() ? true : (*error = tracee.error(), false);
}

// How many times to let the main looper poll before giving up on the bind
// arriving. The system server sends it during attachApplication, so in
// practice it is there at the first or second poll; this only bounds a wrong
// guess about that.
constexpr int kMaxLooperPolls = 64;

// A connected socket to the target, with no name anywhere.
//
// The target makes the pair itself, with a remote syscall, and we take one end
// out of it with pidfd_getfd -- so nothing is ever bound, published or
// connected to. That is the point rather than a flourish: an abstract socket
// the app connected to would put an SELinux `unix_stream_socket connectto`
// check between untrusted_app and this daemon's domain, which stock policy
// denies, and getting around it would mean mislabelling the socket or patching
// policy. A socketpair triggers no such check, because no connect happens. The
// only permission involved is pidfd_getfd's PTRACE_MODE_ATTACH_REALCREDS,
// which we hold because we are ptracing the process at this instant.
//
// Neither end has a name, so no other process can find it: the app's end is
// reachable only from inside that process, and ours only from inside this one.
//
// `theirs` is the descriptor number in the target, which the agent needs so
// Java can adopt it. `ours` is a real descriptor here.
bool OpenChannel(pid_t pid, uint64_t scratch, int* ours, int* theirs, std::string* error) {
  Tracee tracee(pid);
  Borrow borrow(&tracee);

  const int64_t made = borrow.Syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM, 0, scratch);
  if (SyscallFailed(made)) {
    *error = std::string("socketpair in the target failed: ") +
             ::strerror(static_cast<int>(-made));
    return false;
  }

  int pair[2] = {-1, -1};
  if (!tracee.ReadMemory(scratch, pair, sizeof(pair))) {
    *error = tracee.error();
    return false;
  }

  // pidfd_open/pidfd_getfd are 5.6 and have no bionic wrappers at this API
  // level, so they go through syscall() by number.
  const long pidfd = ::syscall(__NR_pidfd_open, pid, 0);
  if (pidfd < 0) {
    *error = std::string("pidfd_open on the target failed: ") + ::strerror(errno);
    return false;
  }
  const long taken = ::syscall(__NR_pidfd_getfd, pidfd, pair[0], 0);
  const int why = errno;
  ::close(static_cast<int>(pidfd));
  if (taken < 0) {
    *error = std::string("pidfd_getfd of the target's socket failed: ") + ::strerror(why);
    return false;
  }

  // The target keeps one end only; ours is a duplicate of the other, and the
  // one it was duplicated from would otherwise sit there holding the channel
  // open from both sides.
  borrow.Syscall(SYS_close, static_cast<uint64_t>(pair[0]));

  *ours = static_cast<int>(taken);
  *theirs = pair[1];
  KS_LOGI("channel to %d: fd %d here, fd %d there", pid, *ours, *theirs);
  return tracee.ok() ? true : (*error = tracee.error(), false);
}

// Stage three: stop the main thread each time it polls, and ask the agent
// whether the app's bind data has arrived yet. The agent does the surgery the
// moment it can see it -- with the process stopped, before the message has
// been dispatched, so nothing about it is a race.
bool InterceptBind(pid_t pid, uint64_t handle, const std::string& activity_class, int64_t deadline,
                   int* channel, uint32_t* steps_taken, int* agent_result, std::string* error) {
  uint64_t entry = 0;
  if (!RemoteSymbol(pid, handle, "keystork_bind", &entry, error)) return false;

  // The class name has to be readable in the target at each call, and the
  // calls happen wherever the stepping stopped -- so it is mapped once, here,
  // rather than at every one of them.
  const auto page = static_cast<size_t>(::getpagesize());
  uint64_t scratch = 0;
  {
    Tracee tracee(pid);
    Borrow borrow(&tracee);
    const int64_t mapped =
        borrow.Syscall(SYS_mmap, 0, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                       static_cast<uint64_t>(-1), 0);
    if (SyscallFailed(mapped)) {
      *error = std::string("could not map scratch for the launch component: ") +
               ::strerror(static_cast<int>(-mapped));
      return false;
    }
    scratch = static_cast<uint64_t>(mapped);
    if (!tracee.WriteMemory(scratch, activity_class.c_str(), activity_class.size() + 1)) {
      *error = tracee.error();
      return false;
    }
  }

  // The channel is opened before the surgery rather than after it: the agent
  // is told the descriptor number as it installs itself, so the number is
  // already there by the time the app's Application asks for it -- which
  // happens after we have detached and can no longer reach into the process.
  // A page's worth of scratch is plenty for both the name and the two ints,
  // which go far enough past it not to overlap.
  int theirs = -1;
  if (!OpenChannel(pid, scratch + page / 2, channel, &theirs, error)) return false;

  int total = 0;
  for (int poll = 1; poll <= kMaxLooperPolls; poll++) {
    int steps = 0;
    if (!StepToSyscallExit(pid, IsLooperPoll(), deadline, &steps, error)) return false;
    total += steps;

    int said = 0;
    if (!CallAgent(pid, entry, "keystork_bind", scratch, static_cast<uint64_t>(theirs), &said,
                   error)) {
      return false;
    }
    if (said < 0) {
      *error = "keystork_bind failed (" + std::to_string(said) + "); see logcat";
      return false;
    }
    if (said > 0) {
      KS_LOGI("took the app's own code off the classpath at poll %d, %d syscalls past the arm",
              poll, total);
      // Nothing of ours should be left mapped in a process that carries on
      // living; the agent has copied the name into a Java String by now.
      Tracee tracee(pid);
      Borrow borrow(&tracee);
      borrow.Syscall(SYS_munmap, scratch, page);

      *steps_taken = static_cast<uint32_t>(total);
      *agent_result = said;
      return true;
    }
  }
  *error = "the app's bind data never reached the main thread in " +
           std::to_string(kMaxLooperPolls) + " polls";
  return false;
}

// Per forked child, while we work out whether it is the one we want.
struct Child {
  bool stepping = false;   // past its initial SIGSTOP
  bool at_entry = true;    // the next syscall stop is an entry rather than an exit
  bool claiming = false;   // matched the setresuid; the next stop is its exit
  int steps = 0;
};

// Detaches, whether or not the tracee is stopped.
//
// This is not a nicety. Every ptrace request except ATTACH, SEIZE, INTERRUPT
// and KILL needs the tracee to be in ptrace-stop, and PTRACE_SEIZE -- unlike
// ATTACH -- deliberately leaves it *running*. So a bare PTRACE_DETACH on a
// seized tracee normally fails with ESRCH and leaves it attached, which for
// the zygote means it is still carrying TRACEFORK: its next fork stops it, and
// with our wait loop over nothing reaps that stop. It then sits there while
// the system server waits for a pid it will never get, holding the activity
// manager's lock, until Watchdog kills the system server sixty seconds later.
//
// PTRACE_INTERRUPT is what makes a running seized tracee stop on demand, so
// the sequence is interrupt, reap whatever stop that produces, then detach.
bool LetGo(pid_t pid) {
  if (::ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == 0) return true;
  if (errno != ESRCH) return false;

  if (::ptrace(PTRACE_INTERRUPT, pid, nullptr, nullptr) != 0) {
    // ESRCH here means it is genuinely gone rather than merely running, which
    // is the one case where being unable to detach is fine.
    return errno == ESRCH;
  }

  for (int attempt = 0; attempt < 64; attempt++) {
    int status = 0;
    if (::waitpid(pid, &status, __WALL) < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (!WIFSTOPPED(status)) return true;  // it died on its own; nothing to do

    // A signal that was about to be delivered is the tracee's, and detaching
    // with 0 would swallow it -- the same mistake that used to leave the
    // zygote's dead children unreaped.
    const int event = (status >> 16) & 0xff;
    const int signal = WSTOPSIG(status);
    const int deliver =
        (event == 0 && signal != SIGTRAP && signal != kSyscallTrap && signal != SIGSTOP) ? signal
                                                                                         : 0;
    if (::ptrace(PTRACE_DETACH, pid, nullptr,
                 reinterpret_cast<void*>(static_cast<long>(deliver))) == 0) {
      return true;
    }
    if (errno != ESRCH) return false;
  }
  return false;
}

// Whether `pid` still has a tracer, which after LetGo should be nobody. Read
// rather than assumed because a zygote we failed to release is a device-wide
// hazard: nothing on it can start an app until this process exits.
bool StillTraced(pid_t pid) {
  char path[64];
  ::snprintf(path, sizeof(path), "/proc/%d/status", pid);
  FILE* status = ::fopen(path, "re");
  if (status == nullptr) return false;

  bool traced = false;
  char line[256];
  while (::fgets(line, sizeof(line), status) != nullptr) {
    int tracer = 0;
    if (::sscanf(line, "TracerPid: %d", &tracer) == 1) {
      traced = tracer != 0;
      break;
    }
  }
  ::fclose(status);
  return traced;
}

// Launches the package and returns the process the zygote forked for it,
// stopped at the exit of the setresuid that gave it its identity.
//
// Nothing about a child at its first stop says which app it is: it is still
// root, and still called zygote64, because both the UID and the name are set
// later during specialization. Stepping it to the setresuid is what turns it
// from "a fork" into "the target", and doing so at a syscall *exit* stop is
// what leaves it somewhere safe to hijack.
pid_t CatchTarget(pid_t zygote, uid_t uid, const std::string& package,
                  const std::string& component, int timeout_ms, std::string* error) {
  // `am` is not itself a zygote child -- it execs app_process, which starts a
  // runtime of its own -- so it can never be confused for the app.
  const pid_t launcher = Spawn({"/system/bin/am", "start", "-n", component});
  if (launcher < 0) {
    *error = "could not launch " + package;
    return -1;
  }
  KS_LOGI("launching %s (helper pid %d), watching for a fork that becomes uid %u", package.c_str(),
          launcher, uid);

  std::map<pid_t, Child> children;
  const int64_t deadline = NowMs() + timeout_ms;

  // waitpid has to block -- polling it would cost a millisecond per syscall
  // step, and there are thousands -- so the timeout arrives as a signal that
  // interrupts it instead.
  struct sigaction alarm {};
  alarm.sa_handler = OnAlarm;
  ::sigemptyset(&alarm.sa_mask);
  alarm.sa_flags = 0;  // deliberately not SA_RESTART
  struct sigaction previous {};
  ::sigaction(SIGALRM, &alarm, &previous);
  g_deadline_passed = 0;
  ::alarm(static_cast<unsigned>(timeout_ms / 1000) + 1);

  pid_t target = -1;
  while (target < 0) {
    if (g_deadline_passed || NowMs() > deadline) {
      *error = package + " did not fork a process that became uid " + std::to_string(uid) +
               " within " + std::to_string(timeout_ms) + "ms";
      break;
    }

    int status = 0;
    const pid_t stopped = ::waitpid(-1, &status, __WALL);
    if (stopped < 0) {
      if (errno == EINTR) continue;
      *error = std::string("waitpid failed while catching the fork: ") + ::strerror(errno);
      break;
    }

    // Our own launcher finishing, not a tracee. This is the collision that has
    // to be handled anywhere waitpid(-1) shares a process with fork+exec.
    if (stopped == launcher) continue;

    if (stopped == zygote) {
      // The zygote's own signals are its business and must be handed back. It
      // reaps the processes it forks off SIGCHLD, so swallowing one -- which
      // resuming with 0 does -- leaves an app that died during our window as a
      // zombie for as long as the device is up. An event stop is not a signal
      // and gets 0; a signal-delivery stop gets its signal.
      const int event = (status >> 16) & 0xff;
      int forward = 0;

      if (event == PTRACE_EVENT_FORK) {
        unsigned long forked = 0;
        if (::ptrace(PTRACE_GETEVENTMSG, zygote, nullptr, &forked) == 0) {
          children.emplace(static_cast<pid_t>(forked), Child{});
          KS_LOGI("zygote forked %lu", forked);
        }
      } else if (event == 0 && WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
        forward = WSTOPSIG(status);
      }

      // Straight back to work: while the zygote is stopped, every app launch
      // on the device is queued behind this loop.
      ::ptrace(PTRACE_CONT, zygote, nullptr,
               reinterpret_cast<void*>(static_cast<long>(forward)));
      continue;
    }

    if (!WIFSTOPPED(status)) {
      children.erase(stopped);
      continue;
    }

    // The child's first stop can beat the zygote's fork event through waitpid,
    // so an unknown pid here is a new child rather than a mistake.
    Child& child = children[stopped];

    if (!child.stepping) {
      child.stepping = true;
      // TRACESYSGOOD is what makes a syscall stop distinguishable from a real
      // SIGTRAP below.
      ::ptrace(PTRACE_SETOPTIONS, stopped, nullptr,
               reinterpret_cast<void*>(PTRACE_O_TRACESYSGOOD));
      ::ptrace(PTRACE_SYSCALL, stopped, nullptr, nullptr);
      continue;
    }

    const int signal = WSTOPSIG(status);
    if (signal != kSyscallTrap) {
      // Somebody else's signal. Forward it, except the SIGSTOP that comes with
      // being attached, which is ours to swallow.
      const int forward = (signal == SIGSTOP || signal == SIGTRAP) ? 0 : signal;
      ::ptrace(PTRACE_SYSCALL, stopped, nullptr,
               reinterpret_cast<void*>(static_cast<long>(forward)));
      continue;
    }

    if (child.claiming) {
      // The exit stop of the setresuid: identity established, and a safe place
      // to borrow the thread from.
      target = stopped;
      break;
    }

    if (child.at_entry) {
      Tracee looking(stopped);
      user_regs_struct registers{};
      if (looking.ReadRegisters(&registers)) {
        const uint64_t number = registers.regs[8];
        if (number == SYS_setresuid || number == SYS_setuid) {
          const uint64_t becoming = registers.regs[0];
          if (becoming == uid) {
            child.claiming = true;
          } else if (becoming != 0) {
            KS_LOGI("child %d is becoming uid %llu, not %u -- letting it go", stopped,
                    static_cast<unsigned long long>(becoming), uid);
            LetGo(stopped);
            children.erase(stopped);
            continue;
          }
        }
      }
    }

    child.at_entry = !child.at_entry;
    if (++child.steps > kMaxStepsPerChild) {
      KS_LOGI("child %d ran %d syscalls without taking a UID -- letting it go", stopped,
              child.steps);
      LetGo(stopped);
      children.erase(stopped);
      continue;
    }
    ::ptrace(PTRACE_SYSCALL, stopped, nullptr, nullptr);
  }

  ::alarm(0);
  ::sigaction(SIGALRM, &previous, nullptr);

  // Anything still being stepped is running, not stopped, so these go through
  // the interrupt path -- a child left attached would freeze at its next
  // syscall with nobody to resume it, which for somebody else's app is a
  // process that never starts.
  for (const auto& entry : children) {
    if (entry.first != target && !LetGo(entry.first)) {
      KS_LOGE("could not let go of %d; it may be stuck", entry.first);
    }
  }

  if (target > 0) {
    // Now that it is ours, make sure it cannot outlive us. Never set on the
    // zygote: this process dying with that flag on it would take the framework
    // down with it.
    ::ptrace(PTRACE_SETOPTIONS, target, nullptr,
             reinterpret_cast<void*>(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL));
    KS_LOGI("caught %s as pid %d, uid %u", package.c_str(), target, uid);
  }
  return target;
}

}  // namespace

bool OpenIntegritySession(const pb::OpenIntegritySessionRequest& request,
                          pb::CommandResponse* response, IntegritySession* session) {
  if (request.package().empty()) {
    FillProtocolError("an integrity session needs a package", response->mutable_error());
    return false;
  }
  const auto uid = static_cast<uid_t>(request.uid());
  const int timeout_ms =
      request.has_timeout_ms() ? static_cast<int>(request.timeout_ms()) : kDefaultTimeoutMs;

  const pid_t zygote = FindZygote();
  if (zygote < 0) {
    FillIdentityError("no zygote64 process on this device", 0, response->mutable_error());
    return false;
  }
  KS_LOGI("zygote64 is pid %d", zygote);

  // Resolved before anything is disturbed: the class half is what the agent
  // has to answer for once the app's own classes are off the classpath, and a
  // package with nothing launchable should say so before we stop it.
  std::string error;
  std::string component;
  std::string activity_class;
  if (!ResolveLaunchActivity(request.package(), &component, &activity_class, &error)) {
    FillIdentityError(error, 0, response->mutable_error());
    return false;
  }
  KS_LOGI("launching %s; the agent answers for %s", component.c_str(), activity_class.c_str());

  // Without this a warm process just receives the intent and nothing forks.
  SpawnAndWait({"/system/bin/am", "force-stop", request.package()});

  // SEIZE rather than ATTACH: it does not stop the tracee, so the device
  // carries on while we watch. No EXITKILL here, ever.
  if (::ptrace(PTRACE_SEIZE, zygote, nullptr, reinterpret_cast<void*>(PTRACE_O_TRACEFORK)) != 0) {
    FillIdentityError(std::string("could not seize the zygote: ") + ::strerror(errno), errno,
                      response->mutable_error());
    return false;
  }

  const pid_t target = CatchTarget(zygote, uid, request.package(), component, timeout_ms, &error);

  // Let go the moment we have what we came for. This is the single most
  // dangerous line in the daemon: a zygote we fail to release is still
  // carrying TRACEFORK, so its next fork stops it with nobody left to reap the
  // stop, and the system server's procStart thread then blocks in
  // attemptZygoteSendArgsAndGetResult holding the lock every process start
  // needs -- until Watchdog kills the system server a minute later and the
  // device appears to reboot. Verified rather than assumed for that reason.
  if (!LetGo(zygote) || StillTraced(zygote)) {
    KS_LOGE("could not release the zygote (%d); no app on this device can start "
            "until this process exits",
            zygote);
  }

  if (target < 0) {
    FillIdentityError(error, 0, response->mutable_error());
    return false;
  }

  // Everything from here happens with the target stopped, so none of it races
  // the app's startup: it runs exactly the functions we ask it to and nothing
  // else. The three stages are the agent in, the runtime reachable, and the
  // app's own code off the classpath.
  uint64_t handle = 0;
  uint32_t arm_steps = 0;
  uint32_t bind_steps = 0;
  int channel = -1;
  bool opened = InjectAgent(target, &handle, &error);

  if (opened) {
    int steps = 0;
    const int64_t deadline = NowMs() + timeout_ms;
    if (!StepToSyscallExit(target, SyscallArgumentIs(SYS_ioctl, 1, kBinderSetMaxThreads), deadline,
                           &steps, &error)) {
      opened = false;
    } else {
      arm_steps = static_cast<uint32_t>(steps);
      KS_LOGI("reached the binder threadpool setup after %d syscalls", steps);

      uint64_t arm = 0;
      int armed = 0;
      if (!RemoteSymbol(target, handle, "keystork_arm", &arm, &error) ||
          !CallAgent(target, arm, "keystork_arm", 0, 0, &armed, &error)) {
        opened = false;
      } else if (armed != 0) {
        error = "keystork_arm reported " + std::to_string(armed) + "; see logcat";
        opened = false;
      } else {
        int bound = 0;
        opened = InterceptBind(target, handle, activity_class, deadline, &channel, &bind_steps,
                               &bound, &error);
      }
    }
  }

  // Resumes it wherever it was stopped, with its own registers back, and drops
  // EXITKILL with the ptrace relationship -- which is what stops this
  // connection ending from taking the app down before we mean it to. It is
  // stopped here rather than running, so the plain detach inside LetGo is the
  // one that fires; the interrupt path is there for the cases that are not.
  if (!LetGo(target)) KS_LOGE("could not detach from %d", target);

  if (!opened) {
    KS_LOGE("could not open an integrity session in %d: %s", target, error.c_str());
    // AMS would restart-loop a process that dies on every launch, and a
    // half-injected one is not something to leave running either.
    SpawnAndWait({"/system/bin/am", "force-stop", request.package()});
    if (channel >= 0) ::close(channel);
    FillIdentityError(error, 0, response->mutable_error());
    return false;
  }

  auto* opened_response = response->mutable_open_integrity_session();
  opened_response->set_pid(target);
  opened_response->set_uid(uid);
  opened_response->set_arm_steps(arm_steps);
  opened_response->set_bind_steps(bind_steps);

  session->channel = channel;
  session->pid = target;
  session->package = request.package();
  return true;
}

// The session itself: bytes from the client to the app and back, until one of
// them stops.
//
// A byte pump and nothing more. The messages are a contract between the Python
// client and the Java in the app -- the daemon has never parsed one and does
// not need to, which is what lets the protocol grow without it changing.
//
// Both directions are polled together for the same reason exec's pump is: a
// blocking read on one side would sit there while the other had something to
// say. Requests here are small and strictly paired, so there is no high-water
// mark to keep -- a stalled reader cannot build a backlog of one message.
int RunIntegritySession(int client_fd, IntegritySession* session) {
  KS_LOGI("integrity session with %s (pid %d) is open", session->package.c_str(), session->pid);

  char chunk[16384];
  bool running = true;
  while (running) {
    pollfd watching[2] = {{client_fd, POLLIN, 0}, {session->channel, POLLIN, 0}};
    if (::poll(watching, 2, -1) < 0) {
      if (errno == EINTR) continue;
      KS_LOGE("poll on the integrity session failed: %s", ::strerror(errno));
      break;
    }

    for (int side = 0; side < 2 && running; side++) {
      if ((watching[side].revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;

      const int from = watching[side].fd;
      const int to = side == 0 ? session->channel : client_fd;
      const ssize_t got = ::read(from, chunk, sizeof(chunk));
      if (got < 0 && errno == EINTR) continue;
      // One line per chunk. The daemon cannot say what it relayed -- it does
      // not parse any of this -- but "how much, which way, when" is the whole
      // of what it can contribute when a session hangs, and a session carries
      // few enough messages for that to stay readable.
      KS_LOGI("relaying %zd bytes %s", got, side == 0 ? "to the app" : "to the client");
      if (got <= 0) {
        // Either the client hung up or the app did. Both end the session:
        // there is no one left to answer, and nothing to answer to.
        KS_LOGI("the %s end closed the integrity session", side == 0 ? "client" : "app");
        running = false;
        break;
      }

      for (ssize_t at = 0; at < got;) {
        const ssize_t put = ::write(to, chunk + at, static_cast<size_t>(got - at));
        if (put > 0) {
          at += put;
          continue;
        }
        if (put < 0 && errno == EINTR) continue;
        KS_LOGE("relay write failed: %s", ::strerror(errno));
        running = false;
        break;
      }
    }
  }

  ::close(session->channel);
  session->channel = -1;

  // The app must not outlive the connection that launched it -- the same rule
  // exec lives by, and for the same reason: nothing else on the device knows
  // this process is there, so a survivor is a process with no owner holding an
  // app's identity. Its own read returns EOF as soon as the channel closes
  // above, and it exits on that; the force-stop is the backstop for an app
  // that has stopped listening.
  SpawnAndWait({"/system/bin/am", "force-stop", session->package});
  KS_LOGI("integrity session with %s ended", session->package.c_str());
  return 0;
}

}  // namespace keystork
