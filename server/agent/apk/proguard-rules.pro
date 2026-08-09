# The agent's classes are found by name, never by reference: the daemon writes
# "keystork.Shell" into the app's bind data, keystork.Loader answers for the
# launched component by name, and the native half binds Agent.socketFd with
# RegisterNatives. R8 sees no reference to any of them, so without this it
# would strip or rename the lot.
-keep class keystork.** { *; }

# Nothing here is ever debugged from a stack trace we cannot rebuild, but a
# renamed frame in a Play SDK exception is a real cost when diagnosing a
# failed token request.
-dontobfuscate
