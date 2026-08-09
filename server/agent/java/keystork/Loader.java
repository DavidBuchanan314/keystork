package keystork;

import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * The class loader the app's {@code LoadedApk} is given, in place of the
 * {@code PathClassLoader} the framework would have built over the app's dex.
 *
 * <p>It carries no code of its own: its parent is the
 * {@code InMemoryDexClassLoader} over our dex, so ordinary delegation finds our
 * classes and then the boot loader. What it adds is one rule — a small,
 * explicit map from names the framework will ask for to names we actually ship.
 * The framework asks for components by the names in the <em>target's</em>
 * manifest; those arrive from the system server in the launch transaction, so
 * nothing the agent writes into the bind data can reach them, and this is where
 * they get answered.
 *
 * <p>In front of the dex loader rather than derived from it because
 * {@code InMemoryDexClassLoader} is final. That is no loss: classes are still
 * defined exactly once, by the loader that holds the dex.
 *
 * <p>The map is deliberately explicit rather than a catch-all. Anything not in
 * it that we also do not ship is a {@code ClassNotFoundException} naming the
 * class, which is the signal that something reached this process that we had
 * not planned for. Answering every unknown name with a stub would turn that
 * signal into silence.
 */
public final class Loader extends ClassLoader {
    private static final String TAG = "keystork-dex";

    private final Map<String, String> substitutes = new HashMap<>();

    /**
     * @param dex the loader holding our dex, which becomes the parent
     * @param pairs flattened requested-name, our-name pairs; a trailing odd one
     *     is ignored, since a half-written pair is a caller bug rather than a
     *     rule to guess at
     */
    public Loader(ClassLoader dex, String[] pairs) {
        super(dex);
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            substitutes.put(pairs[i], pairs[i + 1]);
            Log.i(TAG, "answering " + pairs[i] + " with " + pairs[i + 1]);
        }
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        String substitute = substitutes.get(name);
        if (substitute == null) {
            return super.loadClass(name, resolve);
        }
        Log.i(TAG, "the framework asked for " + name);
        return super.loadClass(substitute, resolve);
    }
}
