package org.local.lidar.binderprobe;

import android.content.Context;
import android.provider.Settings;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;

/** Shares a durable, per-boot reservation between early and late receivers. */
final class BootAttemptGuard {
    private static final String BUDGET = "autoroot_budget_v146";
    private static final String MARKER = "autoroot_attempt_boot_v149";
    static final int MAX_ATTEMPTS = 10;

    static final class Result {
        final boolean reserved;
        final int bootCount;
        final String reason;

        Result(boolean reserved, int bootCount, String reason) {
            this.reserved = reserved;
            this.bootCount = bootCount;
            this.reason = reason;
        }
    }

    private static String readMarker(File marker) throws Exception {
        if (!marker.exists()) return "";
        byte[] bytes = new byte[64];
        try (FileInputStream input = new FileInputStream(marker)) {
            int length = input.read(bytes);
            if (length < 1 || input.read() != -1) return "invalid";
            return new String(bytes, 0, length, StandardCharsets.US_ASCII);
        }
    }

    static Result tryReserve(Context context, String phase) {
        int count;
        try {
            count = Settings.Global.getInt(context.getContentResolver(),
                Settings.Global.BOOT_COUNT, -1);
        } catch (RuntimeException error) {
            return new Result(false, -1, "boot_count_" + error.getClass().getSimpleName());
        }
        if (count < 0) return new Result(false, count, "boot_count_unavailable");
        Context de = context.createDeviceProtectedStorageContext();
        File directory = de.getFilesDir();
        File marker = new File(directory, MARKER);
        File lockFile = new File(directory, MARKER + ".lock");
        File budget = new File(context.getFilesDir(), BUDGET);
        try (RandomAccessFile lockHandle = new RandomAccessFile(lockFile, "rw");
             FileLock ignored = lockHandle.getChannel().lock()) {
            String previous = readMarker(marker);
            if (previous.startsWith(count + ":"))
                return new Result(false, count, "already_attempted_" + previous);
            if ("invalid".equals(previous))
                return new Result(false, count, "invalid_marker");

            int remaining;
            try (FileInputStream input = new FileInputStream(budget)) {
                byte[] value = new byte[3];
                int length = 0;
                int next;
                while (length < value.length && (next = input.read()) != -1)
                    value[length++] = (byte) next;
                String digits = new String(value, 0, length, StandardCharsets.US_ASCII);
                if (input.read() != -1 ||
                    !(digits.matches("[1-9]") || "10".equals(digits)))
                    return new Result(false, count, "budget_empty_or_invalid");
                remaining = Integer.parseInt(digits);
            }

            // Reserve before spending the budget and before touching Binder.
            File markerNext = new File(directory, MARKER + ".tmp");
            try (FileOutputStream output = new FileOutputStream(markerNext)) {
                output.write((count + ":" + phase).getBytes(StandardCharsets.US_ASCII));
                output.getFD().sync();
            }
            if (!markerNext.renameTo(marker))
                return new Result(false, count, "marker_rename_failed");

            File budgetNext = new File(context.getFilesDir(), BUDGET + ".tmp");
            try (FileOutputStream output = new FileOutputStream(budgetNext)) {
                output.write(Integer.toString(remaining - 1)
                    .getBytes(StandardCharsets.US_ASCII));
                output.getFD().sync();
            }
            if (!budgetNext.renameTo(budget))
                return new Result(false, count, "budget_rename_failed");
            return new Result(true, count, "reserved_" + phase);
        } catch (Exception error) {
            return new Result(false, count, "guard_" + error.getClass().getSimpleName());
        }
    }
}
