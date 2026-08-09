package keystork;

import android.app.Application;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;

import com.google.android.gms.tasks.Tasks;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;
import com.google.android.play.core.integrity.StandardIntegrityException;
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest;
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityToken;
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider;
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest;
import com.google.android.play.core.integrity.model.IntegrityErrorCode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import keystork.v1.ClassicTokenRequest;
import keystork.v1.Error;
import keystork.v1.IntegrityRequest;
import keystork.v1.IntegrityResponse;
import keystork.v1.PrepareStandardRequest;
import keystork.v1.StandardPrepared;
import keystork.v1.StandardTokenRequest;
import keystork.v1.TokenIssued;

/**
 * The app's {@code Application}, in place of whatever its manifest named, and
 * the whole of the app for as long as the process lives.
 *
 * <p>The agent writes this class's name into {@code ApplicationInfo.className}
 * before {@code handleBindApplication} reads it, so the framework instantiates
 * this by its ordinary path — no hook, and no app code anywhere in the chain.
 *
 * <p>What that buys is a {@link android.content.Context} and a live main thread
 * inside the app's own process, at the app's own UID: Play Integrity identifies
 * the caller by the package and signing certificate the platform reports for
 * this process, so being here is the entire point.
 */
public final class Shell extends Application {
    private static final String TAG = "keystork-dex";

    /** Guards against a corrupt length turning into a huge allocation. */
    private static final int MAX_FRAME = 1 << 20;

    /**
     * How long to wait on the Play Integrity API before answering with a
     * failure instead.
     *
     * <p>Bounded because an unbounded wait is not just slow, it is dangerous:
     * a session that never answers is a daemon process that never exits, and
     * an injection whose ptrace teardown went wrong stays wrong for as long as
     * that lasts. The API's own round trip is seconds.
     */
    private static final long API_TIMEOUT_SECONDS = 90;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "the app's Application is ours: package=" + getPackageName()
                + " class=" + getClass().getName()
                + " thread=" + Thread.currentThread().getName());

        final int fd = Agent.socketFd();
        if (fd < 0) {
            Log.e(TAG, "no channel to the daemon; nothing to serve");
            return;
        }
        // A thread of its own because every request blocks: Tasks.await on the
        // main thread would stall the looper the SDK's callbacks arrive on.
        new Thread(() -> serve(fd), "keystork").start();
    }

    /**
     * Reads requests until the daemon hangs up, then ends the process.
     *
     * <p>Ending it is not tidiness. Nothing else on the device knows this
     * process is here, so one that outlived its connection would be a process
     * with no owner holding an app's identity — the same rule the daemon's
     * exec'd children live by.
     */
    private void serve(int fd) {
        try (ParcelFileDescriptor channel = ParcelFileDescriptor.adoptFd(fd);
                DataInputStream in =
                        new DataInputStream(new FileInputStream(channel.getFileDescriptor()));
                DataOutputStream out =
                        new DataOutputStream(new FileOutputStream(channel.getFileDescriptor()))) {
            for (;;) {
                IntegrityRequest request;
                try {
                    request = IntegrityRequest.parseFrom(readFrame(in));
                } catch (EOFException end) {
                    Log.i(TAG, "the daemon hung up");
                    break;
                }
                // Logged before the call rather than after it: these take
                // seconds, and a request that never comes back is the failure
                // worth being able to see the start of.
                Log.i(TAG, "request: " + request.getBodyCase());
                IntegrityResponse response = answer(request);
                byte[] encoded = response.toByteArray();
                out.writeInt(encoded.length);
                out.write(encoded);
                out.flush();
                Log.i(TAG, "answered with " + response.getBodyCase() + ", "
                        + encoded.length + " bytes");
            }
        } catch (Throwable problem) {
            Log.e(TAG, "the channel failed", problem);
        }
        Log.i(TAG, "leaving; the session is over");
        Process.killProcess(Process.myPid());
    }

    /** One 4-byte big-endian length, then that many bytes — the daemon's framing. */
    private static byte[] readFrame(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > MAX_FRAME) {
            throw new IOException("frame of " + length + " bytes");
        }
        byte[] frame = new byte[length];
        in.readFully(frame);
        return frame;
    }

    /** The prepared Standard provider, kept because preparing it is the slow half. */
    private StandardIntegrityTokenProvider standardProvider;

    private IntegrityResponse answer(IntegrityRequest request) {
        long started = System.currentTimeMillis();
        try {
            switch (request.getBodyCase()) {
                case CLASSIC:
                    return issued(classic(request.getClassic()), started);
                case PREPARE_STANDARD:
                    prepareStandard(request.getPrepareStandard());
                    return IntegrityResponse.newBuilder()
                            .setPrepareStandard(StandardPrepared.getDefaultInstance())
                            .build();
                case STANDARD:
                    return issued(standard(request.getStandard()), started);
                default:
                    return failed(0, "the request names nothing this agent implements");
            }
        } catch (ExecutionException problem) {
            // What the API actually failed with is the cause; the wrapper says
            // only that something did.
            Throwable why = problem.getCause() == null ? problem : problem.getCause();
            return failed(errorCodeOf(why), why.toString());
        } catch (Throwable problem) {
            return failed(0, problem.toString());
        }
    }

    /** Blocking, and never forever. Safe here because this is not the main thread. */
    private static <T> T await(com.google.android.gms.tasks.Task<T> task) throws Exception {
        return Tasks.await(task, API_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    private String classic(ClassicTokenRequest request) throws Exception {
        IntegrityTokenRequest.Builder building =
                IntegrityTokenRequest.builder().setNonce(request.getNonce());
        if (request.hasCloudProjectNumber()) {
            building.setCloudProjectNumber(request.getCloudProjectNumber());
        }
        IntegrityTokenResponse response = await(
                IntegrityManagerFactory.create(this).requestIntegrityToken(building.build()));
        return response.token();
    }

    private void prepareStandard(PrepareStandardRequest request) throws Exception {
        standardProvider = await(IntegrityManagerFactory.createStandard(this)
                .prepareIntegrityToken(PrepareIntegrityTokenRequest.builder()
                        .setCloudProjectNumber(request.getCloudProjectNumber())
                        .build()));
    }

    private String standard(StandardTokenRequest request) throws Exception {
        if (standardProvider == null) {
            throw new IllegalStateException("no prepared provider; prepare_standard comes first");
        }
        StandardIntegrityToken token = await(standardProvider.request(
                StandardIntegrityTokenRequest.builder()
                        .setRequestHash(request.getRequestHash())
                        .build()));
        return token.token();
    }

    /**
     * The SDK's own error code, kept as the number it is. Naming these belongs
     * to the client, the same as every other error in this protocol.
     */
    private static int errorCodeOf(Throwable why) {
        if (why instanceof com.google.android.play.core.integrity.IntegrityServiceException) {
            return ((com.google.android.play.core.integrity.IntegrityServiceException) why)
                    .getErrorCode();
        }
        if (why instanceof StandardIntegrityException) {
            return ((StandardIntegrityException) why).getErrorCode();
        }
        return IntegrityErrorCode.INTERNAL_ERROR;
    }

    private static IntegrityResponse issued(String token, long started) {
        return IntegrityResponse.newBuilder()
                .setToken(TokenIssued.newBuilder()
                        .setToken(token)
                        .setTookMs((int) (System.currentTimeMillis() - started)))
                .build();
    }

    private static IntegrityResponse failed(int code, String message) {
        Log.e(TAG, "request failed (" + code + "): " + message);
        return IntegrityResponse.newBuilder()
                .setError(Error.newBuilder()
                        .setKind(Error.Kind.INTEGRITY)
                        .setCode(code)
                        .setMessage(message))
                .build();
    }
}
