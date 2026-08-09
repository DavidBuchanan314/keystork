#pragma once

#include <string>

#include <sys/types.h>

#include "keystork.pb.h"

namespace keystork {

// A live integrity session: the app that was launched, and the socket to the
// Java running inside it.
//
// The socket has no name anywhere -- the app made the pair itself under ptrace
// and the daemon took one end with pidfd_getfd -- so nothing else on the
// device can reach either end.
struct IntegritySession {
  int channel = -1;
  pid_t pid = -1;
  std::string package;
};

// Launches the package `request` names, takes the app's own code off every
// classpath in its process before a line of it has run, and leaves our Java
// running there instead. True once the app is up and reachable, with `session`
// filled; false with `response` carrying the error.
//
// Runs in the connection's own child, which is what makes this workable: it is
// already root, already forked, and single-threaded, and every ptrace request
// for a tracee has to come from the one thread that owns it. It dying detaches
// everything it had attached, which is the safety net for the zygote.
bool OpenIntegritySession(const v1::OpenIntegritySessionRequest& request,
                          v1::CommandResponse* response, IntegritySession* session);

// Copies bytes between the client and the app until either stops, then ends
// the app. The daemon parses none of what passes through: the messages are a
// contract between the Python client and the Java in the app.
//
// Returns the connection child's exit status, like the other subprotocols.
int RunIntegritySession(int client_fd, IntegritySession* session);

}  // namespace keystork
