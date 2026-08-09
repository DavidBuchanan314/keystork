package keystork;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

/**
 * What the launch lands on.
 *
 * <p>The process is started because the system server wants a component run,
 * and that component's name is the target's. {@link Loader} answers that name
 * with this, so the launch completes instead of failing on a class that is no
 * longer on any classpath.
 *
 * <p>It finishes immediately: the point of the launch is that the process
 * exists, not that anything is shown.
 */
public final class Blank extends Activity {
    private static final String TAG = "keystork-dex";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Log.i(TAG, "the launch landed here; finishing without drawing anything");
        finish();
    }
}
