package org.local.lidar.binderprobe;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiConfiguration;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Opt-in early network gate. The trial mode is bounded; default is off. */
final class EarlyWifiGate {
    private static final String TAG = "LidarEarlyWifiGate";
    private static final String POLICY = "early_gate_policy_v151";
    private static final String REQUEST = "early_gate_request_v151";
    private static final String READY = "early_gate_ready_v151";
    private static final String KIOSK = "me.jxl.kiosk_satellite";

    private static String exactSmallFile(File path) throws Exception {
        byte[] bytes = new byte[128];
        try (FileInputStream input = new FileInputStream(path)) {
            int count = 0;
            while (count < bytes.length) {
                int next = input.read(bytes, count, bytes.length - count);
                if (next < 0) break;
                count += next;
            }
            if (count == bytes.length || input.read() != -1) return "invalid";
            return new String(bytes, 0, count, StandardCharsets.US_ASCII);
        }
    }

    private static void writeAtomic(File directory, String name, String value)
            throws Exception {
        File next = new File(directory, name + ".tmp");
        File target = new File(directory, name);
        try (FileOutputStream output = new FileOutputStream(next, false)) {
            output.write(value.getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
        }
        if (!next.renameTo(target)) throw new IllegalStateException("rename_failed");
    }

    private static String mode(File directory) throws Exception {
        String policy;
        try { policy = exactSmallFile(new File(directory, POLICY)); }
        catch (java.io.FileNotFoundException missing) { return "off"; }
        if ("mode=trial\n".equals(policy)) return "trial";
        if ("mode=continuous\n".equals(policy)) return "continuous";
        return "off";
    }

    static String prepareRequest(Context context, int bootCount) {
        if (bootCount < 0) return "invalid_boot_count";
        try {
            if (Settings.Global.getInt(context.getContentResolver(), "wifi_on", -1) != 0)
                return "wifi_not_off";
            File directory = context.createDeviceProtectedStorageContext().getFilesDir();
            String selected = mode(directory);
            if ("off".equals(selected)) return "policy_off_or_invalid";
            String request = "boot_count=" + bootCount + "\nmode=" + selected + "\n";
            writeAtomic(directory, REQUEST, request);
            Log.i(TAG, "GATE_REQUESTED boot_count=" + bootCount + " mode=" + selected);
            return "requested_" + selected;
        } catch (Exception error) {
            Log.e(TAG, "GATE_REQUEST_FAILED", error);
            return "request_failed_" + error.getClass().getSimpleName();
        }
    }

    private static boolean waitForIp(WifiManager wifi) {
        long deadline = SystemClock.elapsedRealtime() + 30000L;
        do {
            if (wifi.getWifiState() == WifiManager.WIFI_STATE_ENABLED &&
                wifi.getConnectionInfo() != null &&
                wifi.getConnectionInfo().getIpAddress() != 0) return true;
            SystemClock.sleep(250);
        } while (SystemClock.elapsedRealtime() < deadline);
        return false;
    }

    private static String enableSavedNetwork(WifiManager wifi) {
        // This stock build imports the profile as disabled. Turning on the
        // radio alone cannot associate with it. Only a single saved network
        // is accepted, matching the clean-profile setup in configure_gate.py.
        List<WifiConfiguration> networks = null;
        long deadline = SystemClock.elapsedRealtime() + 5000L;
        do {
            networks = wifi.getConfiguredNetworks();
            if (networks != null) break;
            SystemClock.sleep(250);
        } while (SystemClock.elapsedRealtime() < deadline);
        if (networks == null) return "saved_network_unavailable";
        if (networks.size() != 1 || networks.get(0) == null ||
            networks.get(0).networkId < 0)
            return "saved_network_count_or_id_invalid";
        int id = networks.get(0).networkId;
        if (!wifi.enableNetwork(id, true)) return "saved_network_enable_rejected";
        if (!wifi.reconnect()) return "saved_network_reconnect_rejected";
        Log.i(TAG, "GATE_SAVED_NETWORK_ENABLED id=" + id);
        return "ready";
    }

    static String releaseAfterConfirmedRoot(Context context) {
        String selected = "off";
        WifiManager activatedWifi = null;
        boolean enabledByGate = false;
        try {
            int bootCount = Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.BOOT_COUNT, -1);
            if (bootCount < 0) return "invalid_boot_count";
            int storedWifi = Settings.Global.getInt(context.getContentResolver(),
                "wifi_on", -1);
            if (storedWifi != 0 && storedWifi != 1) return "invalid_wifi_preference";
            File directory = context.createDeviceProtectedStorageContext().getFilesDir();
            selected = mode(directory);
            if ("off".equals(selected)) return "policy_off_or_invalid";
            String expectedRequest = "boot_count=" + bootCount + "\nmode=" + selected + "\n";
            if (!expectedRequest.equals(exactSmallFile(new File(directory, REQUEST))))
                return "not_requested_for_boot";
            int kioskUid = 0;
            try {
                kioskUid = context.getPackageManager().getApplicationInfo(KIOSK, 0).uid;
            } catch (PackageManager.NameNotFoundException absent) {
                // No voice app was requested. The kernel gate allows LAN only.
            }
            String expectedReady = expectedRequest + "filter=ready\n"
                + "kiosk_uid=" + kioskUid + "\n";
            File ready = new File(directory, READY);
            long deadline = SystemClock.elapsedRealtime() + 15000L;
            boolean confirmed = false;
            do {
                try {
                    if (expectedReady.equals(exactSmallFile(ready))) {
                        confirmed = true;
                        break;
                    }
                } catch (java.io.FileNotFoundException pending) {
                    // Root bridge may be up before optional filter commands finish.
                }
                SystemClock.sleep(100);
            } while (SystemClock.elapsedRealtime() < deadline);
            if (!confirmed) return "filter_not_confirmed_within_15s";
            String filterCheck = ProbeService.askRootHelper("GATE_CHECK",
                "GATE_CHECK_V151 rc=0 ");
            if (!filterCheck.startsWith("GATE_CHECK_V151 rc=0 "))
                return "filter_live_check_failed_" + filterCheck;
            WifiManager wifi = (WifiManager) context.getApplicationContext()
                .getSystemService(Context.WIFI_SERVICE);
            boolean alreadyUp = wifi != null &&
                wifi.getWifiState() == WifiManager.WIFI_STATE_ENABLED &&
                wifi.getConnectionInfo() != null &&
                wifi.getConnectionInfo().getIpAddress() != 0;
            boolean accepted = alreadyUp || (wifi != null && wifi.setWifiEnabled(true));
            Log.i(TAG, "GATE_WIFI_REQUEST boot_count=" + bootCount
                + " mode=" + selected + " kiosk_uid=" + kioskUid
                + " already_up=" + alreadyUp + " accepted=" + accepted);
            if (!accepted) return "wifi_request_rejected";
            activatedWifi = wifi;
            enabledByGate = true;
            if (!alreadyUp) {
                String selectedNetwork = enableSavedNetwork(wifi);
                if (!"ready".equals(selectedNetwork)) {
                    if ("continuous".equals(selected)) wifi.setWifiEnabled(false);
                    return selectedNetwork;
                }
            }
            if (!waitForIp(wifi)) {
                if ("continuous".equals(selected)) wifi.setWifiEnabled(false);
                return "wifi_ip_not_seen_within_30s";
            }
            String persisted = ProbeService.askRootHelper("GATE_PERSIST",
                "GATE_PERSIST_V151 rc=0 ");
            Log.i(TAG, "GATE_PERSIST_RESULT boot_count=" + bootCount
                + " result=" + persisted);
            if (persisted.startsWith("GATE_PERSIST_V151 rc=0 "))
                return "wifi_up_nextboot_off_" + selected;
            // A continuous policy may never leave the next cold boot open.
            // Fail closed here; the attached USB recovery path is required.
            if ("continuous".equals(selected)) wifi.setWifiEnabled(false);
            return "persist_failed_" + persisted;
        } catch (Exception error) {
            if (enabledByGate && activatedWifi != null &&
                "continuous".equals(selected)) {
                try { activatedWifi.setWifiEnabled(false); }
                catch (RuntimeException rollbackError) {
                    Log.e(TAG, "GATE_FAIL_CLOSED_WIFI_DISABLE_FAILED", rollbackError);
                }
            }
            Log.e(TAG, "GATE_RELEASE_FAILED", error);
            return "release_failed_" + error.getClass().getSimpleName();
        }
    }
}
