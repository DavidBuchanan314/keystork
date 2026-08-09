#pragma once

#include <sys/types.h>

namespace keystork {

// Serves one connection on `fd` to completion, then returns the exit status the
// child should use.
//
// Called only in a forked child, which has already closed the listening socket.
// The child serves top-level commands as root until one of them hands the
// connection over for good:
//
//   ReadFile -- read part of a file. Only ever valid up here, because it is
//     the root privileges that make it useful.
//
//   OpenKeystoreSession -- permanently drop to the UID it names, open a Binder
//     connection, and serve requests synchronously until the peer disconnects.
//     The child never returns to root and never outlives the connection, which
//     is what keeps sessions single-UID.
//
//   Exec -- fork and exec a program, then carry its stdio in both directions
//     until it exits. This child stays root; it is the grandchild that takes
//     on the requested identity.
//
//   KillServer -- acknowledge, then SIGTERM `supervisor_pid`, which takes down
//     the supervisor and every other session with it.
//
// `supervisor_pid` is passed in rather than read from getppid(), which would
// name init if the supervisor had already exited.
int RunConnection(int fd, pid_t supervisor_pid);

}  // namespace keystork
