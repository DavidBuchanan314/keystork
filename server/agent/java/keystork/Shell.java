package keystork;

import android.app.Application;
import android.util.Log;

/**
 * The app's {@code Application}, in place of whatever its manifest named.
 *
 * <p>The agent writes this class's name into {@code ApplicationInfo.className}
 * before {@code handleBindApplication} reads it, so the framework instantiates
 * this by its ordinary path — no hook, and no app code anywhere in the chain.
 *
 * <p>What it buys beyond suppression is a {@link android.content.Context} and a
 * live main thread inside the app's own process, at the app's own UID, which is
 * what anything we later want to run there needs.
 */
public final class Shell extends Application {
    private static final String TAG = "keystork-dex";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "the app's Application is ours: package=" + getPackageName()
                + " class=" + getClass().getName()
                + " thread=" + Thread.currentThread().getName());
    }
}
