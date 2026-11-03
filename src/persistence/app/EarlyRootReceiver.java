package org.local.lidar.binderprobe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

/** First step of the tested cold-boot path.
 *
 * Android starts this receiver as an ordinary app, before the late boot
 * broadcast. The exact image check and durable reservation below prevent a
 * different build or a second receiver from entering the kernel path.
 * Follow ProbeService's two-stage branch after this file.
 */
public final class EarlyRootReceiver extends BroadcastReceiver {
    private static final String TAG = "LidarEarlyRoot";
    private static final String FINGERPRINT =
        "Amazon/lidar/lidar:6.0/NS6575/8338N:user/amz-p,release-keys";

    @Override public void onReceive(Context context, Intent intent) {
        if (intent == null || !Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(intent.getAction()) ||
            !FINGERPRINT.equals(Build.FINGERPRINT)) return;
        BootAttemptGuard.Result guard = BootAttemptGuard.tryReserve(context, "early");
        Log.i(TAG, "EARLY_ROOT_RESERVE elapsed_ms=" + SystemClock.elapsedRealtime()
            + " boot_count=" + guard.bootCount + " result=" + guard.reason);
        if (!guard.reserved) return;
        Log.i(TAG, "EARLY_GATE_PREPARE boot_count=" + guard.bootCount
            + " result=" + EarlyWifiGate.prepareRequest(context, guard.bootCount));
        Intent service = new Intent(context, ProbeService.class);
        service.putExtra("source", "boot-early-auto-rearm-v149");
        service.putExtra("self_binder_compose_selinux_canary", true);
        service.putExtra("self_binder_compose_two_stage", true);
        try {
            context.startService(service);
        } catch (RuntimeException error) {
            // Keep the budget spent and the guard set. Retrying the kernel
            // path in this boot would be less safe than manual recovery.
            Log.e(TAG, "EARLY_ROOT_SERVICE_START_FAILED", error);
        }
    }
}
