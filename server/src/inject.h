#pragma once

#include "keystork.pb.h"

namespace keystork {

// Launches the package `request` names and loads the embedded agent into it
// before any of the app's own code has run, filling `response` either way.
//
// Runs in the connection's own child, which is what makes this workable: it is
// already root, already forked, and single-threaded, and every ptrace request
// for a tracee has to come from the one thread that owns it. It dying detaches
// everything it had attached, which is the safety net for the zygote.
void HandleInject(const v1::InjectRequest& request, v1::CommandResponse* response);

}  // namespace keystork
