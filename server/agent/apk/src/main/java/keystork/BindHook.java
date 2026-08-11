package keystork;

import android.os.Handler;
import android.os.Message;
import android.util.Log;

/**
 * Intercepts the bind message as it is dispatched, rather than racing to catch
 * it on the queue beforehand.
 *
 * <p>Installed by the native half onto {@code ActivityThread.mH.mCallback}
 * while the process is stopped under ptrace. {@code Handler.dispatchMessage}
 * consults {@code mCallback} before {@code handleMessage}, so this runs on the
 * app's own main thread immediately before {@code handleBindApplication}, with
 * the {@code AppBindData} the framework is about to act on.
 *
 * <p>Why not catch it on the queue: the daemon used to stop the main thread at
 * the looper's poll and rewrite the bind data while it sat there undispatched.
 * That depends on the poll being a syscall, and it is not always one --
 * {@code Looper::pollInner} skips {@code epoll_wait} entirely for a zero
 * timeout with no fd requests, which is exactly the case where the bind is
 * already waiting. There is then no instruction boundary to stop at, the main
 * thread walks into {@code handleBindApplication}, and the app comes up as
 * itself. Dispatch cannot be skipped that way: if the bind is handled at all,
 * this ran first.
 */
public final class BindHook implements Handler.Callback {
    private static final String TAG = "keystork-dex";

    /**
     * Matched on the payload's type rather than on {@code H.BIND_APPLICATION},
     * because the payload is what the surgery needs and the constant is a
     * private number that only happens to be stable.
     */
    private static final String BIND_DATA = "android.app.ActivityThread$AppBindData";

    @Override
    public boolean handleMessage(Message message) {
        final Object payload = message.obj;
        if (payload != null && BIND_DATA.equals(payload.getClass().getName())) {
            Log.i(TAG, "the bind is being dispatched; taking the app's code off the classpath");
            apply(payload);
        }
        // Never true. Returning true tells Handler the message is handled and
        // stops handleBindApplication from ever running, which would leave a
        // process that never becomes an app at all.
        return false;
    }

    /**
     * Rewrites the bind data in place. Bound by the native half with {@code
     * RegisterNatives} at install time, for the same reason {@link
     * Agent#socketFd()} is: the agent is a memfd mapping with no name to load.
     */
    private static native void apply(Object bindData);
}
