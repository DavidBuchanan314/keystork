package keystork;

import android.app.Application;
import android.util.Base64;
import android.util.Log;

import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;

import java.security.SecureRandom;

/**
 * The app's {@code Application}, in place of whatever its manifest named.
 *
 * <p>The agent writes this class's name into {@code ApplicationInfo.className}
 * before {@code handleBindApplication} reads it, so the framework instantiates
 * this by its ordinary path — no hook, and no app code anywhere in the chain.
 *
 * <p>What it buys beyond suppression is a {@link android.content.Context} and a
 * live main thread inside the app's own process, at the app's own UID, which is
 * what everything below needs: Play Integrity identifies the caller by the
 * package and signing certificate the platform reports for this process, so
 * being here is the whole point.
 */
public final class Shell extends Application {
    private static final String TAG = "keystork-dex";

    /** logcat drops a line somewhere past 4 KB, and a token is longer. */
    private static final int CHUNK = 3000;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "the app's Application is ours: package=" + getPackageName()
                + " class=" + getClass().getName()
                + " thread=" + Thread.currentThread().getName());
        requestClassicToken();
    }

    /**
     * The classic request: one call, one token, no warm-up. No cloud project
     * number, which is allowed only for an app Play knows — so a failure here
     * naming that is a statement about the *target*, not about the injection.
     *
     * <p>Asynchronous, and deliberately left that way: the callbacks land on
     * this thread's looper, which is the app's main looper, running normally by
     * the time anything can arrive.
     */
    private void requestClassicToken() {
        final byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        // The nonce has to be URL-safe base64 and unwrapped; 32 random bytes is
        // inside the 16..500 the API accepts once decoded.
        final String nonce =
                Base64.encodeToString(raw, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        Log.i(TAG, "requesting a classic integrity token, nonce=" + nonce);

        try {
            IntegrityManager manager = IntegrityManagerFactory.create(this);
            manager.requestIntegrityToken(IntegrityTokenRequest.builder().setNonce(nonce).build())
                    .addOnSuccessListener(response -> logLong("token", response.token()))
                    .addOnFailureListener(problem -> Log.e(TAG, "the request failed", problem));
        } catch (Throwable problem) {
            // Anything thrown before the Task exists -- a missing class, a
            // Play Store that is not there -- would otherwise take the app's
            // process down through Application.onCreate.
            Log.e(TAG, "the request could not be made at all", problem);
        }
    }

    private static void logLong(String what, String value) {
        Log.i(TAG, what + " is " + value.length() + " chars, in "
                + ((value.length() + CHUNK - 1) / CHUNK) + " parts");
        for (int at = 0, part = 1; at < value.length(); at += CHUNK, part++) {
            Log.i(TAG, what + " " + part + ": "
                    + value.substring(at, Math.min(value.length(), at + CHUNK)));
        }
    }
}
