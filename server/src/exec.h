#pragma once

#include <sys/types.h>

#include "keystork.pb.h"

namespace keystork {

// A running child and the fds its stdio is on.
//
// With a pty there is one device, not three: `out` is the master and `in` is a
// dup of it, so the pump can close, poll and give up on the two directions
// independently without the fd juggling a shared descriptor would need. `err`
// is -1, because a terminal has no second stream.
struct ExecProcess {
  pid_t pid = -1;
  int in = -1;
  int out = -1;
  int err = -1;
  bool pty = false;
};

// Forks and execs what `request` describes, as the UID and GID it names.
// Returns true with `process` filled, or false with `error` filled and nothing
// left running.
//
// A setup step or the execve itself failing is an ordinary error rather than a
// dead session: the child reports its errno back through a close-on-exec pipe,
// which this waits for, so the caller can answer the command normally and
// leave the connection at the top level.
bool StartExec(const v1::ExecRequest& request, ExecProcess* process, v1::Error* error);

// Pumps `process`'s stdio over `fd` until the child exits or the peer hangs
// up, then reaps it and closes its fds. Returns the status the connection's
// child should exit with.
//
// `fd` is switched to non-blocking and stays that way: this is the one place
// in the protocol where both sides talk unprompted, so neither the socket nor
// the child may be allowed to stall the other.
int RunExecSession(int fd, ExecProcess* process);

}  // namespace keystork
