// SPDX-License-Identifier: Apache-2.0
package org.local.echoasrmic;

import android.app.Application;
import android.content.Context;
import android.media.AudioManager;
import android.media.AudioRecordingConfiguration;
import android.os.Process;
import android.util.Log;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import me.jxl.kiosk.plugins.KioskPlugin;
import me.jxl.kiosk.plugins.PluginHost;

/**
 * App-local source-6 selection for the existing Kiosk recorder.
 * Verify the reflected recorder layout and the resulting Android input stream
 * instead of rejecting compatible Kiosk updates solely by version or APK hash.
 * It never opens AudioRecord itself and never reads or stores microphone PCM.
 */
public final class EchoAsrMicPlugin implements KioskPlugin {
    private static final String TAG = "Plus2AsrMic";
    private static final String PACKAGE = "me.jxl.kiosk_satellite";
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final AtomicBoolean deactivating = new AtomicBoolean(false);
    private final Object mutationLock = new Object();
    private volatile PluginHost host;
    private volatile Thread worker;
    private volatile Layout activeLayout;
    private volatile Object ownedPair;
    private volatile Object previousPair;
    private volatile Application application;

    @Override public void start(PluginHost newHost, Map<String, Object> settings) {
        host = newHost;
        stopping.set(false);
        deactivating.set(false);
        worker = new Thread(this::activate, "plus2-asr-mic-start");
        worker.setDaemon(true);
        worker.start();
    }

    @Override public void configure(Map<String, Object> settings) {}

    @Override public void execute(String command, Map<String, Object> arguments) {
        if ("inspect".equals(command)) {
            Thread thread = new Thread(this::inspect, "plus2-asr-mic-inspect");
            thread.setDaemon(true);
            thread.start();
            return;
        }
        if ("deactivate".equals(command)) {
            if (!deactivating.compareAndSet(false, true)) {
                throw new IllegalStateException("deactivation already running");
            }
            Thread thread = new Thread(() -> {
                try {
                    synchronized (mutationLock) {
                        restore(true);
                    }
                    report("ASR_MIC_DEACTIVATED_OK", false);
                } catch (Throwable error) {
                    report("ASR_MIC_DEACTIVATE_ERROR type="
                            + error.getClass().getSimpleName() + " message="
                            + String.valueOf(error.getMessage()), true);
                }
            }, "plus2-asr-mic-deactivate");
            thread.setDaemon(true);
            thread.start();
            return;
        }
        throw new IllegalArgumentException("unknown command");
    }

    private void activate() {
        try {
            Layout layout = checkedLayout();
            synchronized (mutationLock) {
                if (stopping.get() || deactivating.get()) return;
                Object old = layout.fallback.get(null);
                if (old != null && !fallbackDescription(old, layout).startsWith("1:")) {
                    throw new IllegalStateException("unrecognized existing fallback");
                }
                Object shape = layout.shapeConstructor.newInstance(16000, 1, 6);
                Object pair = layout.pairConstructor.newInstance(Integer.valueOf(1), shape);
                layout.fallback.set(null, pair);
                if (layout.fallback.get(null) != pair) {
                    throw new IllegalStateException("fallback writeback differs");
                }
                activeLayout = layout;
                ownedPair = pair;
                previousPair = old;
                report("ASR_MIC_ARMED pair=1:16000x1:6 uid=" + Process.myUid(), false);
            }

            // Plugins start after WakeWordManager, but a voice transaction or
            // Android startup may still delay its listening recorder.
            long deadline = System.nanoTime() + 60_000_000_000L;
            while (!stopping.get() && !deactivating.get() && System.nanoTime() < deadline) {
                Map<?, ?> wake = wakeState();
                if (Boolean.TRUE.equals(wake.get("muted"))) {
                    report("ASR_MIC_ARMED_MUTED; no unmute requested", false);
                    return;
                }
                if (!Boolean.TRUE.equals(wake.get("enabled"))) {
                    report("ASR_MIC_ARMED_WAKE_DISABLED; no unmute requested", false);
                    return;
                }
                if (sourceCount(6) == 1 && sourceCount(1) == 0) {
                    report("ASR_MIC_SOURCE6_ACTIVE; existing recorder", false);
                    return;
                }
                if (Boolean.TRUE.equals(wake.get("listening")) && sourceCount(1) == 1) {
                    synchronized (mutationLock) {
                        if (stopping.get() || deactivating.get()) return;
                        Map<?, ?> current = wakeState();
                        if (!Boolean.TRUE.equals(current.get("listening"))
                                || !Boolean.FALSE.equals(current.get("muted"))) continue;
                        // Kiosk's own control releases and reopens its single
                        // recorder. Never start a parallel AudioRecord here.
                        boolean mutedByPlugin = false;
                        try {
                            // Mark intent before the asynchronous host call:
                            // its callback can time out after muting succeeded.
                            mutedByPlugin = true;
                            setMute(true);
                            Thread.sleep(300);
                        } finally {
                            // Never return or propagate InterruptedException
                            // while our own temporary mute is still active.
                            if (mutedByPlugin) setMute(false);
                        }
                        if (stopping.get() || deactivating.get()) return;
                        awaitListening(4000);
                        if (!awaitSources(6, 1, 6000)) {
                            throw new IllegalStateException("source 6 not confirmed after reopen");
                        }
                        report("ASR_MIC_SOURCE6_ACTIVE; Kiosk recorder reopened", false);
                        return;
                    }
                }
                Thread.sleep(400);
            }
            if (!stopping.get() && !deactivating.get()) {
                throw new IllegalStateException("Kiosk recorder did not become available within 60s");
            }
        } catch (Throwable error) {
            report("ASR_MIC_ACTIVATE_ERROR type=" + error.getClass().getSimpleName()
                    + " message=" + String.valueOf(error.getMessage()), true);
            try {
                synchronized (mutationLock) { restore(true); }
                report("ASR_MIC_FAILBACK_OK", false);
            } catch (Throwable restoreError) {
                report("ASR_MIC_FAILBACK_ERROR type="
                        + restoreError.getClass().getSimpleName() + " message="
                        + String.valueOf(restoreError.getMessage()), true);
            }
        }
    }

    private void inspect() {
        try {
            Layout layout = checkedLayout();
            Object current = layout.fallback.get(null);
            Map<?, ?> wake = wakeState();
            report("ASR_MIC_INSPECT fallback=" + fallbackDescription(current, layout)
                    + " source1=" + sourceCount(1) + " source6=" + sourceCount(6)
                    + " enabled=" + wake.get("enabled") + " listening=" + wake.get("listening")
                    + " muted=" + wake.get("muted"), false);
        } catch (Throwable error) {
            report("ASR_MIC_INSPECT_ERROR type=" + error.getClass().getSimpleName()
                    + " message=" + String.valueOf(error.getMessage()), true);
        }
    }

    private void restore(boolean reopen) throws Exception {
        Layout layout = activeLayout;
        Object pair = ownedPair;
        if (layout == null || pair == null) return;
        Object current = layout.fallback.get(null);
        if (current != pair
                && !"1:16000x1:6".equals(fallbackDescription(current, layout))) {
            // Kiosk may replace our Pair with an equal Pair after hearing
            // real audio on the fallback. Other changes are not ours.
            throw new IllegalStateException("fallback ownership lost");
        }
        Map<?, ?> wake = null;
        boolean shouldReopen = false;
        if (reopen && host != null) {
            wake = wakeState();
            shouldReopen = Boolean.TRUE.equals(wake.get("listening"))
                    && Boolean.FALSE.equals(wake.get("muted"))
                    && sourceCount(6) == 1;
        }
        boolean mutedByPlugin = false;
        try {
            if (shouldReopen) {
                mutedByPlugin = true;
                setMute(true);
                Thread.sleep(300);
            }
            layout.fallback.set(null, previousPair);
            if (layout.fallback.get(null) != previousPair) {
                throw new IllegalStateException("fallback restore readback differs");
            }
            ownedPair = null;
            activeLayout = null;
            previousPair = null;
        } finally {
            if (mutedByPlugin) setMute(false);
        }
        if (shouldReopen) {
            awaitListening(4000);
            if (!awaitSources(1, 6, 6000)) {
                throw new IllegalStateException("source 1 not confirmed after restore");
            }
        }
        report("ASR_MIC_SOURCE1_RESTORED reopened=" + shouldReopen
                + " muted_unchanged=" + !shouldReopen, false);
    }

    private int sourceCount(int source) {
        Application app = application;
        if (app == null) return 0;
        AudioManager audio = (AudioManager) app.getSystemService(Context.AUDIO_SERVICE);
        int count = 0;
        List<AudioRecordingConfiguration> all = audio.getActiveRecordingConfigurations();
        for (AudioRecordingConfiguration configuration : all) {
            if (configuration.getClientAudioSource() == source) count++;
        }
        return count;
    }

    private boolean awaitSources(int wanted, int unwanted, long maxMs) throws InterruptedException {
        long deadline = System.nanoTime() + maxMs * 1_000_000L;
        while (System.nanoTime() < deadline) {
            if (sourceCount(wanted) == 1 && sourceCount(unwanted) == 0) return true;
            Thread.sleep(150);
        }
        return false;
    }

    private static final class Layout {
        final Field fallback;
        final Constructor<?> shapeConstructor;
        final Constructor<?> pairConstructor;
        final Field pairFirst;
        final Field pairSecond;
        final Field shapeRate;
        final Field shapeChannels;
        final Field shapeSource;

        Layout(Field fallback, Constructor<?> shapeConstructor, Constructor<?> pairConstructor,
                Field pairFirst, Field pairSecond, Field shapeRate, Field shapeChannels,
                Field shapeSource) {
            this.fallback = fallback;
            this.shapeConstructor = shapeConstructor;
            this.pairConstructor = pairConstructor;
            this.pairFirst = pairFirst;
            this.pairSecond = pairSecond;
            this.shapeRate = shapeRate;
            this.shapeChannels = shapeChannels;
            this.shapeSource = shapeSource;
        }
    }

    private Layout checkedLayout() throws Exception {
        Class<?> thread = Class.forName("android.app.ActivityThread");
        Method current = thread.getDeclaredMethod("currentApplication");
        Application app = (Application) current.invoke(null);
        if (app == null || !PACKAGE.equals(app.getPackageName())) {
            throw new IllegalStateException("wrong Android app context");
        }
        ClassLoader loader = app.getClassLoader();
        Class<?> recorder = Class.forName(PACKAGE + ".MicRecorder", false, loader);
        Class<?> shape = Class.forName(PACKAGE + ".MicRecorder$Shape", false, loader);
        Class<?> pair = Class.forName("kotlin.Pair", false, loader);
        if (recorder.getClassLoader() != loader || shape.getClassLoader() != loader) {
            throw new IllegalStateException("recorder classloader mismatch");
        }
        Field fallback = recorder.getDeclaredField("provenFallback");
        int flags = fallback.getModifiers();
        if (!Modifier.isStatic(flags) || !Modifier.isVolatile(flags)
                || fallback.getType() != pair) {
            throw new IllegalStateException("fallback field layout mismatch");
        }
        fallback.setAccessible(true);
        Constructor<?> shapeConstructor = shape.getDeclaredConstructor(int.class, int.class, int.class);
        Constructor<?> pairConstructor = pair.getDeclaredConstructor(Object.class, Object.class);
        Field rate = shape.getDeclaredField("rateHz");
        Field channels = shape.getDeclaredField("channels");
        Field source = shape.getDeclaredField("source");
        if (rate.getType() != int.class || channels.getType() != int.class
                || source.getType() != int.class) {
            throw new IllegalStateException("shape field layout mismatch");
        }
        Field first = pair.getDeclaredField("first");
        Field second = pair.getDeclaredField("second");
        first.setAccessible(true);
        second.setAccessible(true);
        rate.setAccessible(true);
        channels.setAccessible(true);
        source.setAccessible(true);
        application = app;
        return new Layout(fallback, shapeConstructor, pairConstructor,
                first, second, rate, channels, source);
    }

    private static String fallbackDescription(Object value, Layout layout) throws Exception {
        if (value == null) return "none";
        Object first = layout.pairFirst.get(value);
        Object second = layout.pairSecond.get(value);
        if (!(first instanceof Number) || second == null
                || !layout.shapeRate.getDeclaringClass().isInstance(second)) return "unknown";
        return ((Number) first).intValue() + ":"
                + layout.shapeRate.getInt(second) + "x"
                + layout.shapeChannels.getInt(second) + ":"
                + layout.shapeSource.getInt(second);
    }

    private Object command(String name, Map<String, Object> args) throws Exception {
        PluginHost current = host;
        if (current == null) throw new IllegalStateException("plugin host gone");
        CountDownLatch done = new CountDownLatch(1);
        final boolean[] success = {false};
        final Object[] data = {null};
        final String[] error = {null};
        current.executeCommand(name, args, (ok, value, why) -> {
            success[0] = ok;
            data[0] = value;
            error[0] = why;
            done.countDown();
        });
        if (!done.await(6, TimeUnit.SECONDS)) throw new IllegalStateException(name + " timeout");
        if (!success[0]) throw new IllegalStateException(name + " rejected: " + error[0]);
        return data[0];
    }

    private Map<?, ?> wakeState() throws Exception {
        Object data = command("getWakeWordState", Collections.emptyMap());
        if (!(data instanceof Map)) throw new IllegalStateException("wake state malformed");
        return (Map<?, ?>) data;
    }

    private void setMute(boolean muted) throws Exception {
        Map<String, Object> args = new HashMap<>();
        args.put("muted", muted);
        Object result = command("setWakeWordMuted", args);
        if (!Boolean.valueOf(muted).equals(result)) {
            throw new IllegalStateException("mute result mismatch");
        }
        report("ASR_MIC_MUTE " + muted, false);
    }

    private void awaitListening(long maxMs) throws Exception {
        long deadline = System.nanoTime() + maxMs * 1_000_000L;
        while (System.nanoTime() < deadline) {
            Map<?, ?> state = wakeState();
            if (Boolean.TRUE.equals(state.get("listening"))
                    && Boolean.FALSE.equals(state.get("muted"))) return;
            Thread.sleep(200);
        }
        throw new IllegalStateException("wake word did not resume");
    }

    private void report(String line, boolean error) {
        Log.i(TAG, line);
        PluginHost current = host;
        if (current != null) {
            try {
                current.log(line);
                current.status(line, error);
            } catch (RuntimeException ignored) {
                // Plugin disable revokes the host before stop(). Logcat remains.
            }
        }
    }

    @Override public void onEvent(String event, Map<String, Object> payload) {}

    @Override public void stop() {
        stopping.set(true);
        // A plugin lifecycle callback has a three-second deadline. The host
        // is already revoked here, so only restore the static field; the
        // manager's explicit deactivate command must reopen an active track.
        Thread cleanup = new Thread(() -> {
            synchronized (mutationLock) {
                Layout layout = activeLayout;
                Object pair = ownedPair;
                if (layout != null && pair != null) {
                    try {
                        Object currentPair = layout.fallback.get(null);
                        if (currentPair == pair || "1:16000x1:6".equals(
                                fallbackDescription(currentPair, layout))) {
                            layout.fallback.set(null, previousPair);
                            Log.i(TAG, "ASR_MIC_STOP_FALLBACK_RESTORED; open recorder needs normal reopen");
                        }
                    } catch (Exception error) {
                        Log.e(TAG, "ASR_MIC_STOP_RESTORE_ERROR", error);
                    }
                }
                activeLayout = null;
                ownedPair = null;
                previousPair = null;
            }
        }, "plus2-asr-mic-stop-cleanup");
        cleanup.setDaemon(true);
        cleanup.start();
        host = null;
    }
}
