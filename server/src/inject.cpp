#include "inject.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <android/dlext.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
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
// landmark is.
constexpr int kMaxStepsPerChild = 20000;

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

// Where in the target to call, and what to tell the linker the caller was.
struct Loader {
  uint64_t function = 0;
  uint64_t caller = 0;
  bool takes_caller = false;
  std::string symbol;
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

// The linker decides which namespace a dlopen runs in from the *caller's*
// address, and a call driven by ptrace has no caller -- our LR points at a
// PROT_NONE trap page. __loader_android_dlopen_ext exists precisely so the
// caller can be stated outright, so it is the one to want. Falling back to the
// public entry point means whatever the linker infers from that trap address,
// which may or may not be the namespace the library needs.
bool ResolveLoader(pid_t pid, Loader* out, std::string* error) {
  struct Candidate {
    const char* symbol;
    bool takes_caller;
  };
  static const Candidate kCandidates[] = {
      {"__loader_android_dlopen_ext", true},
      {"android_dlopen_ext", false},
  };

  for (const Candidate& candidate : kCandidates) {
    void* local = ::dlsym(RTLD_DEFAULT, candidate.symbol);
    if (local == nullptr) continue;

    std::string module;
    uint64_t remote = 0;
    if (!Relocate(pid, local, &remote, &module)) continue;

    out->function = remote;
    out->takes_caller = candidate.takes_caller;
    out->symbol = candidate.symbol;

    // Any address inside a real library will do: the linker only uses it to
    // find the soinfo that owns it, and libc is in the default namespace,
    // which is all there is this early.
    if (candidate.takes_caller && !FindModuleBase(pid, "/libc.so", &out->caller)) {
      out->takes_caller = false;
    }
    KS_LOGI("dlopen entry point %s from %s at %#llx (caller %#llx)", candidate.symbol,
            module.c_str(), static_cast<unsigned long long>(out->function),
            static_cast<unsigned long long>(out->caller));
    return true;
  }

  *error = "no android_dlopen_ext entry point could be resolved";
  return false;
}

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

bool InjectAgent(pid_t pid, pb::InjectResponse* response, std::string* error) {
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

  Loader loader;
  if (!ResolveLoader(pid, &loader, error)) return false;

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

  switch (call.outcome) {
    case CallResult::Outcome::kReturned:
      response->set_outcome(pb::InjectResponse::RETURNED);
      response->set_handle(call.value);
      if (call.value == 0) {
        const std::string reason = RemoteDlerror(pid, &tracee, &borrow);
        KS_LOGE("the linker refused the agent: %s",
                reason.empty() ? "(no dlerror)" : reason.c_str());
      }
      // Only reachable when the agent did not _exit, so there is still a
      // process to tidy up after.
      borrow.Syscall(SYS_close, fd);
      borrow.Syscall(SYS_munmap, static_cast<uint64_t>(scratch), page);
      break;

    case CallResult::Outcome::kExited:
      // The expected result: the agent's constructor called _exit, so dlopen
      // never returned and there is nothing left to clean up.
      response->set_outcome(pb::InjectResponse::EXITED);
      response->set_exit_status(call.status);
      break;

    case CallResult::Outcome::kFaulted:
      response->set_outcome(pb::InjectResponse::FAULTED);
      response->set_fault_signal(call.signal);
      response->set_fault_address(call.fault_address);
      break;

    case CallResult::Outcome::kFailed:
      *error = tracee.ok() ? "the call into the linker failed" : tracee.error();
      return false;
  }
  return true;
}

// Per forked child, while we work out whether it is the one we want.
struct Child {
  bool stepping = false;   // past its initial SIGSTOP
  bool at_entry = true;    // the next syscall stop is an entry rather than an exit
  bool claiming = false;   // matched the setresuid; the next stop is its exit
  int steps = 0;
};

void LetGo(pid_t pid) { ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr); }

// Launches the package and returns the process the zygote forked for it,
// stopped at the exit of the setresuid that gave it its identity.
//
// Nothing about a child at its first stop says which app it is: it is still
// root, and still called zygote64, because both the UID and the name are set
// later during specialization. Stepping it to the setresuid is what turns it
// from "a fork" into "the target", and doing so at a syscall *exit* stop is
// what leaves it somewhere safe to hijack.
pid_t CatchTarget(pid_t zygote, uid_t uid, const std::string& package, int timeout_ms,
                  std::string* error) {
  // Resolving the launcher activity here rather than in the client keeps this
  // to one spawn, and `am` is not itself a zygote child -- it execs
  // app_process, which starts a runtime of its own -- so it cannot be confused
  // for the app.
  const pid_t launcher =
      Spawn({"/system/bin/sh", "-c",
             "exec /system/bin/am start -n \"$(/system/bin/cmd package resolve-activity "
             "--brief " +
                 package + " | tail -1)\""});
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
      if (WIFSTOPPED(status) && status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
        unsigned long forked = 0;
        if (::ptrace(PTRACE_GETEVENTMSG, zygote, nullptr, &forked) == 0) {
          children.emplace(static_cast<pid_t>(forked), Child{});
          KS_LOGI("zygote forked %lu", forked);
        }
      }
      // Straight back to work: while the zygote is stopped, every app launch
      // on the device is queued behind this loop.
      ::ptrace(PTRACE_CONT, zygote, nullptr, nullptr);
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

  for (const auto& entry : children) {
    if (entry.first != target) LetGo(entry.first);
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

void HandleInject(const pb::InjectRequest& request, pb::CommandResponse* response) {
  if (request.package().empty()) {
    FillProtocolError("inject needs a package", response->mutable_error());
    return;
  }
  const auto uid = static_cast<uid_t>(request.uid());
  const int timeout_ms =
      request.has_timeout_ms() ? static_cast<int>(request.timeout_ms()) : kDefaultTimeoutMs;

  const pid_t zygote = FindZygote();
  if (zygote < 0) {
    FillIdentityError("no zygote64 process on this device", 0, response->mutable_error());
    return;
  }
  KS_LOGI("zygote64 is pid %d", zygote);

  // Without this a warm process just receives the intent and nothing forks.
  SpawnAndWait({"/system/bin/am", "force-stop", request.package()});

  // SEIZE rather than ATTACH: it does not stop the tracee, so the device
  // carries on while we watch. No EXITKILL here, ever.
  if (::ptrace(PTRACE_SEIZE, zygote, nullptr, reinterpret_cast<void*>(PTRACE_O_TRACEFORK)) != 0) {
    FillIdentityError(std::string("could not seize the zygote: ") + ::strerror(errno), errno,
                      response->mutable_error());
    return;
  }

  std::string error;
  const pid_t target = CatchTarget(zygote, uid, request.package(), timeout_ms, &error);

  // Let go the moment we have what we came for; nothing else on the device can
  // start an app until we do.
  ::ptrace(PTRACE_DETACH, zygote, nullptr, nullptr);

  if (target < 0) {
    FillIdentityError(error, 0, response->mutable_error());
    return;
  }

  auto* result = response->mutable_inject();
  result->set_pid(target);
  result->set_uid(uid);

  const bool injected = InjectAgent(target, result, &error);
  ::ptrace(PTRACE_DETACH, target, nullptr, nullptr);

  // The process died during startup, so AMS will want to restart it. This is
  // what stops that becoming a loop.
  SpawnAndWait({"/system/bin/am", "force-stop", request.package()});

  if (!injected) {
    KS_LOGE("injection into %d failed: %s", target, error.c_str());
    FillIdentityError(error, 0, response->mutable_error());
  }
}

}  // namespace keystork
