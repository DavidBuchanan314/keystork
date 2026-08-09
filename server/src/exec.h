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

// How an exec session ended, and whether the connection survives it.
enum class ExecOutcome {
  kChildExited,  // reaped, output drained, ExecExit sent -- the connection is usable
  kClientGone,   // the peer hung up, so the child was killed; nothing left to talk to
  kFailed,       // the machinery broke
};

// Pumps `process`'s stdio over `fd` until the child exits or the peer hangs
// up, then reaps it and closes its fds.
//
// `fd` is non-blocking for the duration -- this is the one place in the
// protocol where both sides talk unprompted, so neither the socket nor the
// child may be allowed to stall the other -- and blocking again on the way
// out, because the top level reads with blocking calls.
//
// On kChildExited the connection goes back to the top level, and anything read
// past the last frame this consumed comes back in `leftover` -- bytes already
// off the socket, which the command loop has to see. They need no
// interpretation here: exec_input is an arm of Command, so an input sent just
// before the exit and a command sent just after are the same kind of message.
ExecOutcome RunExecSession(int fd, ExecProcess* process, std::string* leftover);

}  // namespace keystork
