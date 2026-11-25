package org.local.lidar.binderprobe;

import android.os.Build;

/** Selects a captured kernel image independently of its A/B slot. */
final class KernelProfile {
    static final int NS6575_8338N = 1;
    static final int NS6536_2509N = 2;
    static final int NS6541_2965N = 3;
    static final int NS65741_8149N = 4;

    private static final String[] FINGERPRINTS = {
        "",
        "Amazon/lidar/lidar:6.0/NS6575/8338N:user/amz-p,release-keys",
        "Amazon/lidar/lidar:6.0/NS6536/2509N:user/amz-p,release-keys",
        "Amazon/lidar/lidar:6.0/NS6541/2965N:user/amz-p,release-keys",
        "Amazon/lidar/lidar:6.0/NS65741/8149N:user/amz-p,release-keys",
    };
    private static native int nativeProfileId();

    final int id;

    private KernelProfile(int id) { this.id = id; }

    static KernelProfile detect() {
        // Preserve the already tested 8338N boot path. It previously needed
        // only the exact build fingerprint and did not open /proc/version.
        if (FINGERPRINTS[NS6575_8338N].equals(Build.FINGERPRINT))
            return new KernelProfile(NS6575_8338N);

        if (!FINGERPRINTS[NS6536_2509N].equals(Build.FINGERPRINT) &&
            !FINGERPRINTS[NS6541_2965N].equals(Build.FINGERPRINT) &&
            !FINGERPRINTS[NS65741_8149N].equals(Build.FINGERPRINT)) return null;
        try {
            System.loadLibrary("binderprobe");
            int id = nativeProfileId();
            if (id >= NS6536_2509N && id <= NS65741_8149N &&
                FINGERPRINTS[id].equals(Build.FINGERPRINT))
                return new KernelProfile(id);
        } catch (LinkageError ignored) { }
        return null;
    }
}
