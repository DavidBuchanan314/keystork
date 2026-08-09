#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <sys/types.h>
#include <sys/user.h>

namespace keystork {

// A stopped thread, and the machinery for driving it: read and write its
// memory, and borrow it to run syscalls of our own.
//
// Nothing here attaches, stops or resumes anything -- whoever owns the
// ptrace relationship owns those. This is only the "now that it is stopped,
// make it do something" half.
//
// aarch64 only, and deliberately: the register layout, the syscall ABI and
// the instruction width are all baked in below, and a 32-bit target would
// need a different one of each.
class Tracee {
 public:
  explicit Tracee(pid_t tid) : tid_(tid) {}

  pid_t tid() const { return tid_; }

  // process_vm_readv/writev, so no descriptor and one syscall per transfer.
  //
  // The writes cannot reach a read-only mapping: process_vm_writev does not
  // use FOLL_FORCE, which is exactly why /proc/pid/mem is what debuggers plant
  // breakpoints with. Fine for writing into a mapping we asked the tracee to
  // make; not a way to patch text.
  bool ReadMemory(uint64_t address, void* out, size_t length);
  bool WriteMemory(uint64_t address, const void* data, size_t length);

  // Where an `svc #0` lives in this thread's [vdso]. Resolved on first use and
  // cached; 0 if it could not be found, with the reason in error().
  uint64_t SyscallInstruction();

  // Set by any failure of the machinery itself, and sticky. A syscall the
  // kernel *refused* is not this -- that comes back as a negative errno in the
  // result, the same as the kernel gives libc.
  bool ok() const { return error_.empty(); }
  const std::string& error() const { return error_; }
  void Fail(const std::string& message);

 private:
  pid_t tid_;
  uint64_t syscall_instruction_ = 0;
  bool syscall_instruction_resolved_ = false;
  std::string error_;
};

// Where a file is loaded in `tid`, matched by the tail of its path -- so
// "/libc.so" finds it wherever the apex has put it this release. The mapping
// at file offset zero, which is the one holding the ELF header and therefore
// the base every other address in the file is relative to.
//
// The point of this is the offset trick: a library mapped in both this process
// and the tracee is the same image at two addresses, so a symbol resolved
// locally with dlsym is (symbol - local_base + remote_base) over there.
bool FindModuleBase(pid_t tid, const char* path_suffix, uint64_t* base);

// What became of a Borrow::Call.
struct CallResult {
  enum class Outcome {
    kReturned,  // came back to the trap page; `value` is x0
    kExited,    // the tracee died during the call; `status` is the wait status
    kFaulted,   // faulted somewhere else; `signal` and `fault_address` say where
    kFailed,    // the machinery broke; Tracee::error() says why
  };

  Outcome outcome = Outcome::kFailed;
  uint64_t value = 0;
  int status = 0;
  int signal = 0;
  uint64_t fault_address = 0;

  bool returned() const { return outcome == Outcome::kReturned; }
};

std::string Describe(const CallResult& result);

// Borrows a stopped thread: saves its registers, runs what you ask for, and
// puts them back when it goes out of scope. The tracee resumes none the wiser.
//
// The thread must be stopped somewhere it is safe to hijack -- a signal-stop,
// a group-stop, or a syscall-*exit* stop, where its own syscall has finished
// and x0 is just a value to save and restore.
//
// Not a syscall-*entry* stop. There the kernel has already latched a number in
// regs->syscallno which moving pc does not undo, so the tracee's own syscall
// would run before ours. Step to the exit stop first, or cancel it by writing
// -1 through NT_ARM_SYSTEM_CALL -- the same regset that is the reason writing
// x8 at an entry stop is silently ignored on this architecture.
class Borrow {
 public:
  explicit Borrow(Tracee* tracee);
  ~Borrow();

  Borrow(const Borrow&) = delete;
  Borrow& operator=(const Borrow&) = delete;

  // Runs `number` in the tracee and returns the raw kernel result: the value
  // before libc would have turned a negative into errno and -1. So
  // `result < 0 && result > -4096` is the failure case, and -result is the
  // errno.
  //
  // Returns -1 with the tracee failed if the machinery broke; check
  // Tracee::ok() at the end of a sequence rather than after every call.
  int64_t Syscall(long number, uint64_t a0 = 0, uint64_t a1 = 0, uint64_t a2 = 0,
                  uint64_t a3 = 0, uint64_t a4 = 0, uint64_t a5 = 0);

  // Calls a function in the tracee, on a stack of our own rather than on
  // whichever one the thread happened to be stopped on.
  //
  // That is not tidiness. dlopen -- the reason this exists -- maps segments,
  // relocates, and runs the constructors of the library and everything it
  // pulls in, which is arbitrary code with an arbitrary appetite for stack.
  // Borrowing the tracee's SP bets on how much headroom that particular thread
  // had left, and a thread stopped inside a signal handler is on a sigaltstack,
  // which is small by construction.
  //
  // The mapping is [guard][stack][trap], all PROT_NONE but the middle. LR
  // points at the trap page, so a normal return faults on instruction fetch
  // there; running off the bottom faults in the guard page instead. Two pages
  // rather than one so that a blown stack cannot be read as a return.
  //
  // Allocated on first use and unmapped when this Borrow ends, so nothing is
  // left behind in the target. Arguments beyond the sixth would have to go on
  // that stack; nothing here needs them yet.
  CallResult Call(uint64_t function, uint64_t a0 = 0, uint64_t a1 = 0, uint64_t a2 = 0,
                  uint64_t a3 = 0, uint64_t a4 = 0, uint64_t a5 = 0);

 private:
  bool EnsureCallStack();

  Tracee* tracee_;
  user_regs_struct saved_{};
  bool holding_ = false;

  uint64_t stack_ = 0;        // base of the whole mapping, guard page included
  size_t stack_bytes_ = 0;
  uint64_t stack_top_ = 0;    // initial sp: full-descending, so the trap page
  uint64_t return_trap_ = 0;
};

// True when `result` from Borrow::Syscall is one of the kernel's negative
// errnos rather than a value.
inline bool SyscallFailed(int64_t result) { return result < 0 && result > -4096; }

}  // namespace keystork
