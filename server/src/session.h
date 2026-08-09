#pragma once

namespace keystork {

// Runs one UID-scoped session on `fd` to completion, then returns the exit
// status the child should use.
//
// Called only in a forked child, which has already closed the listening
// socket. The child reads the handshake, permanently drops to the UID it names,
// opens its own Binder connection, and then serves requests synchronously until
// the peer disconnects. It never returns to root, and it never outlives the
// connection -- that is what keeps sessions single-UID.
int RunSession(int fd);

}  // namespace keystork
