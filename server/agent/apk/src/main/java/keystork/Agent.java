package keystork;

import android.os.Build;
import android.util.Log;

/**
 * The Java half of the agent.
 *
 * <p>Compiled to a dex at build time, embedded in the agent's .rodata, and
 * loaded by the native half through an {@code InMemoryDexClassLoader} over a
 * direct {@code ByteBuffer} onto those bytes. It never exists as a file: the
 * agent itself reached the target through a memfd, and this is inside it.
 *
 * <p>The loader is parented to the boot ClassLoader rather than the app's, so
 * that nothing here can resolve against the app's own copy of a library --
 * which for the Play Integrity SDK would be a shrunk and renamed one.
 *
 * <p>Keep this small and boring. It is compiled with android.jar on the
 * classpath rather than the bootclasspath, so {@code java.*} resolves against
 * the host JDK: a method added after Android's copy of a class will compile
 * cleanly here and fail at runtime on the device.
 */
public final class Agent {
    private static final String TAG = "keystork-dex";

    private Agent() {}

    /**
     * Our end of the socket to the daemon, as a raw descriptor.
     *
     * <p>Bound by the native half with {@code RegisterNatives} rather than by
     * {@code System.loadLibrary}, which could not work: the agent is a mapping
     * of a memfd and has no name for the runtime to load it by.
     *
     * <p>The daemon opened it by having this process call {@code socketpair}
     * while it was stopped, then taking the far end with {@code pidfd_getfd}.
     * Nothing was ever bound or connected, so no other process can reach it.
     *
     * @return the descriptor, or -1 if the daemon did not open one
     */
    public static native int socketFd();

    /** Reports what the runtime looks like from inside managed code. */
    public static String probe() {
        Log.i(TAG, "running from a dex the daemon shipped");

        StringBuilder chain = new StringBuilder();
        for (ClassLoader loader = Agent.class.getClassLoader();
                loader != null;
                loader = loader.getParent()) {
            if (chain.length() > 0) {
                chain.append(" -> ");
            }
            chain.append(loader.getClass().getName());
        }

        return "thread=" + Thread.currentThread().getName()
                + " sdk=" + Build.VERSION.SDK_INT
                + " loaders=" + chain;
    }
}
