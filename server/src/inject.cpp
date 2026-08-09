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

  switch (call.outcome) {
    case CallResult::Outcome::kReturned:
      response->set_outcome(pb::InjectResponse::RETURNED);
      response->set_handle(call.value);
      if (call.value == 0) {
        const std::string reason = RemoteDlerror(pid, &tracee, &borrow);
        KS_LOGE("the linker refused the agent: %s",
                reason.empty() ? "(no dlerror)" : reason.c_str());
      }
      // The linker has mapped what it needs, so the descriptor can go. The
      // scratch page deliberately stays: the library name lived in it, and
      // bionic is believed to copy that rather than retain the pointer, but
      // being wrong would mean the app crashing on some later dl_iterate_phdr
      // rather than here. One page is not worth that.
      borrow.Syscall(SYS_close, fd);
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
bool CallAgent(pid_t pid, uint64_t function, const char* symbol, uint64_t argument,
               int* agent_result, std::string* error) {
  Tracee tracee(pid);
  Borrow borrow(&tracee);

  const CallResult called = borrow.Call(function, argument);
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

// Stage three: stop the main thread each time it polls, and ask the agent
// whether the app's bind data has arrived yet. The agent does the surgery the
// moment it can see it -- with the process stopped, before the message has
// been dispatched, so nothing about it is a race.
bool InterceptBind(pid_t pid, uint64_t handle, const std::string& activity_class, int64_t deadline,
                   uint32_t* steps_taken, int* agent_result, std::string* error) {
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

  int total = 0;
  for (int poll = 1; poll <= kMaxLooperPolls; poll++) {
    int steps = 0;
    if (!StepToSyscallExit(pid, IsLooperPoll(), deadline, &steps, error)) return false;
    total += steps;

    int said = 0;
    if (!CallAgent(pid, entry, "keystork_bind", scratch, &said, error)) return false;
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

void LetGo(pid_t pid) { ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr); }

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

  // Resolved before anything is disturbed: the class half is what the agent
  // has to answer for once the app's own classes are off the classpath, and a
  // package with nothing launchable should say so before we stop it.
  std::string error;
  std::string component;
  std::string activity_class;
  if (!ResolveLaunchActivity(request.package(), &component, &activity_class, &error)) {
    FillIdentityError(error, 0, response->mutable_error());
    return;
  }
  KS_LOGI("launching %s; the agent answers for %s", component.c_str(), activity_class.c_str());

  // Without this a warm process just receives the intent and nothing forks.
  SpawnAndWait({"/system/bin/am", "force-stop", request.package()});

  // SEIZE rather than ATTACH: it does not stop the tracee, so the device
  // carries on while we watch. No EXITKILL here, ever.
  if (::ptrace(PTRACE_SEIZE, zygote, nullptr, reinterpret_cast<void*>(PTRACE_O_TRACEFORK)) != 0) {
    FillIdentityError(std::string("could not seize the zygote: ") + ::strerror(errno), errno,
                      response->mutable_error());
    return;
  }

  const pid_t target =
      CatchTarget(zygote, uid, request.package(), component, timeout_ms, &error);

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

  bool injected = InjectAgent(target, result, &error);

  // Second stage. Still attached, so none of this races the app: the target is
  // stopped except while running exactly the function we asked it to.
  if (injected && result->outcome() == pb::InjectResponse::RETURNED && result->handle() != 0) {
    int steps = 0;
    const int64_t deadline = NowMs() + timeout_ms;
    if (!StepToSyscallExit(target, SyscallArgumentIs(SYS_ioctl, 1, kBinderSetMaxThreads), deadline,
                           &steps, &error)) {
      injected = false;
    } else {
      result->set_arm_steps(static_cast<uint32_t>(steps));
      KS_LOGI("reached the binder threadpool setup after %d syscalls", steps);

      uint64_t arm = 0;
      int agent_result = 0;
      if (!RemoteSymbol(target, result->handle(), "keystork_arm", &arm, &error) ||
          !CallAgent(target, arm, "keystork_arm", 0, &agent_result, &error)) {
        injected = false;
      } else {
        result->set_arm_result(agent_result);
        KS_LOGI("keystork_arm -> %d", agent_result);

        // Third stage: the bind. Everything the app would have run is named in
        // a message that has not been dispatched yet.
        uint32_t bind_steps = 0;
        int bind_result = 0;
        if (!InterceptBind(target, result->handle(), activity_class, deadline, &bind_steps,
                           &bind_result, &error)) {
          injected = false;
        } else {
          result->set_bind_steps(bind_steps);
          result->set_bind_result(bind_result);
        }
      }
    }
  }

  // Resumes it wherever it was stopped, with its own registers back.
  // Specialization or startup carries on and the app boots. EXITKILL goes with
  // the ptrace relationship, so detaching is also what stops this connection
  // ending from taking the app with it.
  ::ptrace(PTRACE_DETACH, target, nullptr, nullptr);

  // Only when the process did not survive: AMS would otherwise keep restarting
  // something that dies every time. A process that came back from dlopen is
  // meant to carry on booting, and force-stopping it would undo the point.
  if (!injected || result->outcome() != pb::InjectResponse::RETURNED) {
    SpawnAndWait({"/system/bin/am", "force-stop", request.package()});
  }

  if (!injected) {
    KS_LOGE("injection into %d failed: %s", target, error.c_str());
    FillIdentityError(error, 0, response->mutable_error());
  }
}

}  // namespace keystork
