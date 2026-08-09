#include "tracee.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>

#include <elf.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "log.h"

namespace keystork {
namespace {

// `svc #0`. A64 is fixed-width and always four-byte aligned, so a scan for
// this word can only land on a real instruction boundary.
constexpr uint32_t kSvc0 = 0xD4000001u;

bool GetRegisters(pid_t tid, user_regs_struct* out) {
  iovec io{out, sizeof(*out)};
  return ::ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
}

bool SetRegisters(pid_t tid, const user_regs_struct& in) {
  iovec io{const_cast<user_regs_struct*>(&in), sizeof(in)};
  return ::ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0;
}

// Walks /proc/<tid>/maps, handing each line's fields to `match` until it
// returns true. Nothing here is cached: every one of these is a different
// address in every process.
template <typename Match>
bool ScanMaps(pid_t tid, Match match) {
  char path[64];
  ::snprintf(path, sizeof(path), "/proc/%d/maps", tid);
  FILE* maps = ::fopen(path, "re");
  if (maps == nullptr) return false;

  bool found = false;
  char line[1024];
  while (!found && ::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long start = 0, end = 0, offset = 0;
    int name_at = -1;
    // The name is whatever is left after the six fixed fields, which is how a
    // path with spaces in it survives; %n records where that starts.
    if (::sscanf(line, "%llx-%llx %*s %llx %*s %*s %n", &start, &end, &offset, &name_at) < 3) {
      continue;
    }
    const char* name = name_at < 0 ? "" : line + name_at;
    char* newline = ::strchr(const_cast<char*>(name), '\n');
    if (newline != nullptr) *newline = '\0';
    found = match(start, end, offset, name);
  }
  ::fclose(maps);
  return found;
}

bool FindVdso(pid_t tid, uint64_t* start, uint64_t* end) {
  return ScanMaps(tid, [&](uint64_t from, uint64_t to, uint64_t, const char* name) {
    if (::strcmp(name, "[vdso]") != 0) return false;
    *start = from;
    *end = to;
    return true;
  });
}

std::string Hex(uint64_t value) {
  char text[32];
  ::snprintf(text, sizeof(text), "%#llx", static_cast<unsigned long long>(value));
  return text;
}

// How far into the vDSO the first `svc #0` sits.
//
// Scanned in *this* process, once: the vDSO is one image the kernel maps into
// everything, so the contents are identical everywhere and only the base
// differs. That is what makes this a local read instead of a remote one, and
// it is only true because 32-bit targets are out of scope -- those get the
// compat image, which is a different object entirely.
//
// Something in there is guaranteed: __kernel_rt_sigreturn is
// `mov x8, #__NR_rt_sigreturn; svc #0` and cannot be absent, and each of the
// clock_gettime-family fallbacks ends in one too.
//
// Returns SIZE_MAX if the vDSO has no svc, which would mean the assumption
// above has stopped holding.
size_t LocalSyscallOffset(size_t* vdso_length) {
  static size_t cached_length = 0;
  static const size_t cached_offset = [] {
    uint64_t start = 0, end = 0;
    if (!FindVdso(::getpid(), &start, &end)) {
      KS_LOGE("no [vdso] in this process's own maps");
      return SIZE_MAX;
    }
    cached_length = static_cast<size_t>(end - start);

    const auto* words = reinterpret_cast<const uint32_t*>(start);
    const size_t count = cached_length / sizeof(uint32_t);
    for (size_t i = 0; i < count; i++) {
      if (words[i] == kSvc0) return i * sizeof(uint32_t);
    }
    KS_LOGE("no `svc #0` anywhere in this process's %zu-byte [vdso]", cached_length);
    return SIZE_MAX;
  }();

  *vdso_length = cached_length;
  return cached_offset;
}

// Waits for the next stop, retrying through EINTR. False means the tracee is
// gone rather than stopped.
bool WaitForStop(pid_t tid, int* status) {
  for (;;) {
    const pid_t seen = ::waitpid(tid, status, __WALL);
    if (seen == tid) return WIFSTOPPED(*status);
    if (seen < 0 && errno == EINTR) continue;
    return false;
  }
}

// A megabyte, which is what a pthread gets by default and therefore what any
// library's constructors are entitled to assume they are running on.
constexpr size_t kCallStackBytes = 1024 * 1024;

}  // namespace

bool FindModuleBase(pid_t tid, const char* path_suffix, uint64_t* base) {
  const size_t suffix_length = ::strlen(path_suffix);
  return ScanMaps(tid, [&](uint64_t from, uint64_t, uint64_t offset, const char* name) {
    // File offset zero is the mapping holding the ELF header, which is the
    // base the file's own addresses are relative to. The later mappings of the
    // same file are its other segments and would give an answer that is wrong
    // by however large the first one was.
    if (offset != 0) return false;
    const size_t length = ::strlen(name);
    if (length < suffix_length) return false;
    if (::strcmp(name + length - suffix_length, path_suffix) != 0) return false;
    *base = from;
    return true;
  });
}

bool FindModuleForAddress(pid_t tid, uint64_t address, std::string* path, uint64_t* base) {
  std::string found;
  const bool located = ScanMaps(tid, [&](uint64_t from, uint64_t to, uint64_t, const char* name) {
    if (address < from || address >= to || name[0] == '\0' || name[0] == '[') return false;
    found = name;
    return true;
  });
  if (!located) return false;
  // The mapping the address landed in is some segment of the file; the base is
  // the offset-zero one, which may well be a different line.
  if (!FindModuleBase(tid, found.c_str(), base)) return false;
  *path = found;
  return true;
}

std::string Describe(const CallResult& result) {
  switch (result.outcome) {
    case CallResult::Outcome::kReturned:
      return "returned " + Hex(result.value);
    case CallResult::Outcome::kExited:
      if (WIFSIGNALED(result.status)) {
        return "the tracee was killed by signal " + std::to_string(WTERMSIG(result.status));
      }
      return "the tracee exited with status " + std::to_string(WEXITSTATUS(result.status));
    case CallResult::Outcome::kFaulted:
      return "faulted with signal " + std::to_string(result.signal) + " at " +
             Hex(result.fault_address);
    case CallResult::Outcome::kFailed:
      return "failed";
  }
  return "unknown";
}

void Tracee::Fail(const std::string& message) {
  if (error_.empty()) error_ = message;
}

bool Tracee::ReadMemory(uint64_t address, void* out, size_t length) {
  iovec local{out, length};
  iovec remote{reinterpret_cast<void*>(address), length};
  const ssize_t got = ::process_vm_readv(tid_, &local, 1, &remote, 1, 0);
  if (got == static_cast<ssize_t>(length)) return true;
  Fail("could not read " + std::to_string(length) + " bytes at " + std::to_string(address) +
       " from " + std::to_string(tid_) + ": " + ::strerror(errno));
  return false;
}

bool Tracee::WriteMemory(uint64_t address, const void* data, size_t length) {
  iovec local{const_cast<void*>(data), length};
  iovec remote{reinterpret_cast<void*>(address), length};
  const ssize_t put = ::process_vm_writev(tid_, &local, 1, &remote, 1, 0);
  if (put == static_cast<ssize_t>(length)) return true;
  Fail("could not write " + std::to_string(length) + " bytes at " + std::to_string(address) +
       " in " + std::to_string(tid_) + ": " + ::strerror(errno));
  return false;
}

bool Tracee::ReadRegisters(user_regs_struct* out) {
  if (GetRegisters(tid_, out)) return true;
  Fail("could not read registers of " + std::to_string(tid_) + ": " + ::strerror(errno));
  return false;
}

uint64_t Tracee::SyscallInstruction() {
  if (syscall_instruction_resolved_) return syscall_instruction_;
  syscall_instruction_resolved_ = true;

  size_t local_length = 0;
  const size_t offset = LocalSyscallOffset(&local_length);
  if (offset == SIZE_MAX) {
    Fail("no `svc #0` in this process's [vdso] to borrow an address from");
    return 0;
  }

  uint64_t start = 0, end = 0;
  if (!FindVdso(tid_, &start, &end)) {
    Fail("no [vdso] mapped in " + std::to_string(tid_));
    return 0;
  }

  // The offset only transfers because both processes were handed the same
  // image. A different size means they were not -- a 32-bit tracee being the
  // way that happens -- and jumping to the offset anyway would put pc in the
  // middle of something arbitrary.
  const size_t length = static_cast<size_t>(end - start);
  if (length != local_length) {
    Fail("[vdso] in " + std::to_string(tid_) + " is " + std::to_string(length) +
         " bytes but this process's is " + std::to_string(local_length) +
         "; the tracee is not the same architecture");
    return 0;
  }

  syscall_instruction_ = start + offset;
  return syscall_instruction_;
}

Borrow::Borrow(Tracee* tracee) : tracee_(tracee) {
  if (!tracee_->ok()) return;
  if (!GetRegisters(tracee_->tid(), &saved_)) {
    tracee_->Fail(std::string("could not read registers: ") + ::strerror(errno));
    return;
  }
  holding_ = true;
}

Borrow::~Borrow() {
  // Before the registers go back, because unmapping has to borrow them.
  if (holding_ && stack_ != 0) Syscall(SYS_munmap, stack_, stack_bytes_);

  // Put them back even if something failed part-way: a tracee left with our
  // pc and arguments in place is far worse than one that simply did not get
  // what we asked for.
  if (holding_ && !SetRegisters(tracee_->tid(), saved_)) {
    KS_LOGE("could not restore registers of %d: %s", tracee_->tid(), ::strerror(errno));
  }
}

bool Borrow::EnsureCallStack() {
  if (stack_ != 0) return true;

  // The tracee's page size, not a constant: mprotect wants page-aligned
  // bounds, and 16 KiB pages are arriving.
  const size_t page = static_cast<size_t>(::getpagesize());
  const size_t usable = (kCallStackBytes + page - 1) / page * page;
  const size_t total = usable + 2 * page;

  const int64_t base = Syscall(SYS_mmap, 0, total, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                               static_cast<uint64_t>(-1), 0);
  if (SyscallFailed(base)) {
    tracee_->Fail("could not map a call stack in " + std::to_string(tracee_->tid()) + ": " +
                  ::strerror(static_cast<int>(-base)));
    return false;
  }

  const uint64_t trap = static_cast<uint64_t>(base) + page + usable;
  const int64_t guarded = Syscall(SYS_mprotect, static_cast<uint64_t>(base), page, PROT_NONE);
  const int64_t trapped = Syscall(SYS_mprotect, trap, page, PROT_NONE);
  if (SyscallFailed(guarded) || SyscallFailed(trapped)) {
    tracee_->Fail("could not protect the call stack's guard pages in " +
                  std::to_string(tracee_->tid()));
    Syscall(SYS_munmap, static_cast<uint64_t>(base), total);
    return false;
  }

  stack_ = static_cast<uint64_t>(base);
  stack_bytes_ = total;
  // Full-descending, so sp starts at the trap page and the first push lands on
  // the last usable word below it.
  stack_top_ = trap;
  return_trap_ = trap;
  return true;
}

CallResult Borrow::Call(uint64_t function, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5) {
  CallResult result;
  if (!holding_ || !tracee_->ok()) return result;
  if (!EnsureCallStack()) return result;

  user_regs_struct registers = saved_;
  registers.regs[0] = a0;
  registers.regs[1] = a1;
  registers.regs[2] = a2;
  registers.regs[3] = a3;
  registers.regs[4] = a4;
  registers.regs[5] = a5;
  // A frame pointer inherited from the tracee would point into a stack this
  // call is not running on, so anything that tries to unwind -- an exception,
  // a crash handler -- would walk a chain of nonsense. End it here instead.
  registers.regs[29] = 0;
  registers.regs[30] = return_trap_;
  registers.sp = stack_top_;
  registers.pc = function;

  if (!SetRegisters(tracee_->tid(), registers)) {
    tracee_->Fail("could not set up a call to " + Hex(function) + ": " + ::strerror(errno));
    return result;
  }

  int deliver = 0;
  for (;;) {
    if (::ptrace(PTRACE_CONT, tracee_->tid(), nullptr,
                 reinterpret_cast<void*>(static_cast<long>(deliver))) != 0) {
      tracee_->Fail("could not resume into " + Hex(function) + ": " + ::strerror(errno));
      return result;
    }
    deliver = 0;

    int status = 0;
    if (!WaitForStop(tracee_->tid(), &status)) {
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        // Not necessarily a failure: an agent whose constructor calls _exit
        // never lets dlopen return, and that is the point of it.
        holding_ = false;
        stack_ = 0;
        result.outcome = CallResult::Outcome::kExited;
        result.status = status;
        return result;
      }
      tracee_->Fail("lost track of " + std::to_string(tracee_->tid()) + " during a call to " +
                    Hex(function));
      return result;
    }

    const int signal = WSTOPSIG(status);
    if (signal != SIGSEGV && signal != SIGBUS && signal != SIGILL && signal != SIGTRAP) {
      // Somebody else's signal. Hand it back rather than swallow it -- the
      // tracee is entitled to whatever it would have done with it.
      deliver = signal;
      continue;
    }

    siginfo_t information{};
    uint64_t address = 0;
    if (::ptrace(PTRACE_GETSIGINFO, tracee_->tid(), nullptr, &information) == 0) {
      address = reinterpret_cast<uint64_t>(information.si_addr);
    }

    if (signal == SIGSEGV && address == return_trap_) {
      if (!GetRegisters(tracee_->tid(), &registers)) {
        tracee_->Fail(std::string("could not read the result of a call: ") + ::strerror(errno));
        return result;
      }
      result.outcome = CallResult::Outcome::kReturned;
      result.value = registers.regs[0];
      return result;
    }

    // Anything else that faulted is the called code crashing, not it
    // returning. The signal stays pending on the tracee and is suppressed
    // when whoever owns the ptrace relationship resumes it with 0 -- which is
    // what we want, since we caused it.
    result.outcome = CallResult::Outcome::kFaulted;
    result.signal = signal;
    result.fault_address = address;
    return result;
  }
}

int64_t Borrow::Syscall(long number, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5) {
  if (!holding_ || !tracee_->ok()) return -1;

  const uint64_t svc = tracee_->SyscallInstruction();
  if (svc == 0) return -1;

  // Every call starts from the registers as they were, so a sequence of them
  // cannot accumulate leftovers from each other.
  user_regs_struct registers = saved_;
  registers.regs[0] = a0;
  registers.regs[1] = a1;
  registers.regs[2] = a2;
  registers.regs[3] = a3;
  registers.regs[4] = a4;
  registers.regs[5] = a5;
  registers.regs[8] = static_cast<uint64_t>(number);
  registers.pc = svc;

  if (!SetRegisters(tracee_->tid(), registers)) {
    tracee_->Fail(std::string("could not set up syscall ") + std::to_string(number) + ": " +
                  ::strerror(errno));
    return -1;
  }

  // Executing the instruction rather than rewriting a latched syscall number
  // is the whole point: the number is read out of x8 by the entry path as the
  // svc runs, so NT_PRSTATUS is all this needs.
  for (int stop = 0; stop < 2; stop++) {
    if (::ptrace(PTRACE_SYSCALL, tracee_->tid(), nullptr, nullptr) != 0) {
      tracee_->Fail(std::string("could not step syscall ") + std::to_string(number) + ": " +
                    ::strerror(errno));
      return -1;
    }
    int status = 0;
    if (!WaitForStop(tracee_->tid(), &status)) {
      // exit_group and friends never come back, and the registers this holds
      // no longer belong to anything.
      holding_ = false;
      tracee_->Fail("tracee " + std::to_string(tracee_->tid()) + " did not stop after syscall " +
                    std::to_string(number) + " (status " + std::to_string(status) + ")");
      return -1;
    }
  }

  if (!GetRegisters(tracee_->tid(), &registers)) {
    tracee_->Fail(std::string("could not read the result of syscall ") + std::to_string(number) +
                  ": " + ::strerror(errno));
    return -1;
  }
  return static_cast<int64_t>(registers.regs[0]);
}

}  // namespace keystork
