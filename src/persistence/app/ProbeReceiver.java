package org.local.lidar.binderprobe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;

public final class ProbeReceiver extends BroadcastReceiver {
    private static final String TAG = "LidarLateRoot";
    @Override public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            if (!"Amazon/lidar/lidar:6.0/NS6575/8338N:user/amz-p,release-keys"
                    .equals(Build.FINGERPRINT)) return;
            BootAttemptGuard.Result guard = BootAttemptGuard.tryReserve(context, "late");
            Log.i(TAG, "LATE_ROOT_RESERVE elapsed_ms=" + SystemClock.elapsedRealtime()
                + " boot_count=" + guard.bootCount + " result=" + guard.reason);
            if (!guard.reserved) return;
            Intent service = new Intent(context, ProbeService.class);
            service.putExtra("source", "boot-auto-rearm-v147");
            service.putExtra("self_binder_compose_selinux_canary", true);
            service.putExtra("self_binder_compose_two_stage", true);
            try {
                context.startService(service);
            } catch (RuntimeException error) {
                Log.e(TAG, "LATE_ROOT_SERVICE_START_FAILED", error);
            }
        }
    }
}
