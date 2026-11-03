// SPDX-License-Identifier: Apache-2.0
package org.local.echoled;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import me.jxl.kiosk.plugins.KioskPlugin;
import me.jxl.kiosk.plugins.PluginHost;

/** Echo Plus 2 voice-state indicator using only stock, preloaded patterns. */
public final class EchoVoiceLedPlugin implements KioskPlugin {
    private static final String LEDCTRL = "/system/bin/ledctrl";
    private static final String STALE_STARTUP_PATTERN = "anim_start_phase2";
    private PluginHost host;
    private ExecutorService worker;
    private boolean running;
    private boolean voiceEventSeen;
    private boolean wakeEventSeen;
    private boolean muted;
    private String voiceState = "reading";
    private String ownedPattern;
    private String ledStatus = "idle";
    private AspBeamObserver beamObserver;
    private boolean beamObserved;
    private int beamIndex = -1;
    private String beamStatus = "waiting for ASP";
    private long generation;
    private long volumeReadSequence;
    private long volumeGeneration;
    private String volumePattern;
    private Integer lastMasterVolume;
    private Integer lastMediaVolume;
    private String volumeStatus = "waiting";

    @Override public synchronized void start(PluginHost newHost, Map<String, Object> settings) {
        host = newHost;
        running = true;
        voiceEventSeen = false;
        wakeEventSeen = false;
        beamObserved = false;
        beamIndex = -1;
        beamStatus = "waiting for ASP";
        worker = Executors.newSingleThreadExecutor(new ThreadFactory() {
            @Override public Thread newThread(Runnable task) {
                Thread thread = new Thread(task, "echo-plus2-voice-led");
                thread.setDaemon(true);
                return thread;
            }
        });
        host.publishSensor("beam_index", "Native beam index", Collections.<String, Object>emptyMap(), null);
        worker.execute(this::connectBeamObserver);
        worker.execute(this::clearStaleStartupPattern);
        host.subscribe("voice.state");
        host.subscribe("wakeword.state");
        host.subscribe("device.volume");
        readVolume(false);
        host.executeCommand("getVoiceState", Collections.<String, Object>emptyMap(), (ok, data, error) -> {
            String initial = "unknown";
            if (ok && data instanceof Map) {
                Map<?, ?> value = (Map<?, ?>) data;
                initial = Boolean.TRUE.equals(value.get("enabled"))
                    ? String.valueOf(value.get("state")) : "disabled";
            }
            synchronized (EchoVoiceLedPlugin.this) {
                if (!running || voiceEventSeen) return;
                updateState(initial);
            }
        });
        host.executeCommand("getWakeWordState", Collections.<String, Object>emptyMap(),
                (ok, data, error) -> {
                    if (!ok || !(data instanceof Map)) return;
                    synchronized (EchoVoiceLedPlugin.this) {
                        if (!running || wakeEventSeen) return;
                        updateMuted(Boolean.TRUE.equals(((Map<?, ?>) data).get("muted")));
                    }
                });
        report();
    }

    private void clearStaleStartupPattern() {
        String observed = command("--get_active_patterns");
        if (!observed.endsWith("getPattern: " + STALE_STARTUP_PATTERN)) return;
        synchronized (this) {
            if (!running || ownedPattern != null) return;
        }
        String result = command("--unset_pattern=" + STALE_STARTUP_PATTERN);
        synchronized (this) {
            if (!running) return;
            ledStatus = "unset stale startup: " + result;
            report();
        }
    }

    private void connectBeamObserver() {
        AspBeamObserver observer;
        try {
            observer = AspBeamObserver.open(new AspBeamObserver.Sink() {
                @Override public void onBeam(int index) { onBeamIndex(index); }
                @Override public void onUnavailable(String reason) { onBeamUnavailable(reason); }
            });
        } catch (Exception error) {
            synchronized (this) {
                if (!running) return;
                beamStatus = "ASP unavailable: " + error.getClass().getSimpleName();
                report();
            }
            return;
        }
        synchronized (this) {
            if (running) {
                beamObserver = observer;
                if (!beamObserved) beamStatus = "ASP listener registered";
                report();
                return;
            }
        }
        observer.close();
    }

    private synchronized void onBeamIndex(int index) {
        if (!running) return;
        boolean first = !beamObserved;
        beamObserved = true;
        beamIndex = index;
        beamStatus = "ASP index " + index;
        host.publishSensor("beam_index", "Native beam index", Collections.<String, Object>emptyMap(),
                Double.valueOf(index));
        // The native ledcontroller independently receives this event and
        // rotates active-start. This listener only gates that pointed pattern.
        if (first && "listening".equals(voiceState) && !muted) queuePatternUpdate();
        report();
    }

    private synchronized void onBeamUnavailable(String reason) {
        if (!running) return;
        beamObserved = false;
        beamIndex = -1;
        beamStatus = reason;
        host.publishSensor("beam_index", "Native beam index", Collections.<String, Object>emptyMap(), null);
        if ("listening".equals(voiceState) && !muted) queuePatternUpdate();
        report();
    }

    private String patternFor(String state) {
        if (muted) return "mics-off_on";
        // Show a pointed sector only after this boot has produced a real
        // native beam event. Stock ledcontroller performs the rotation.
        if ("listening".equals(state)) return beamObserved ? "active-start" : "scone-active";
        if ("processing".equals(state)) return "active-thinking";
        if ("responding".equals(state)) return "active-talking";
        return null;
    }

    private synchronized void updateState(String state) {
        if (!running) return;
        if (state.equals(voiceState)) return;
        voiceState = state;
        volumePattern = null;
        queuePatternUpdate();
        report();
    }

    private synchronized void updateMuted(boolean next) {
        if (!running || muted == next) return;
        muted = next;
        volumePattern = null;
        queuePatternUpdate();
        report();
    }

    private void queuePatternUpdate() {
        final long sequence = ++generation;
        final String wanted = volumePattern != null ? volumePattern : patternFor(voiceState);
        worker.execute(() -> apply(sequence, wanted));
    }

    private synchronized void readVolume(boolean display) {
        if (!running) return;
        final long readSequence = ++volumeReadSequence;
        host.executeCommand("getVolume", Collections.<String, Object>emptyMap(), (ok, data, error) -> {
            if (!ok || !(data instanceof Number)) return;
            final int master = ((Number) data).intValue();
            host.executeCommand("getVolume", Collections.<String, Object>singletonMap("channel", "media"),
                    (mediaOk, mediaData, mediaError) -> {
                if (!mediaOk || !(mediaData instanceof Number)) return;
                int media = ((Number) mediaData).intValue();
                synchronized (EchoVoiceLedPlugin.this) {
                    if (!running || readSequence != volumeReadSequence ||
                            master < 0 || master > 100 || media < 0 || media > 100) return;
                    boolean masterChanged = lastMasterVolume != null && master != lastMasterVolume;
                    boolean mediaChanged = lastMediaVolume != null && media != lastMediaVolume;
                    lastMasterVolume = master;
                    lastMediaVolume = media;
                    if (!display || muted || !"idle".equals(voiceState) ||
                            (!masterChanged && !mediaChanged)) return;
                    // Hardware buttons change master; Music Assistant/Spotify
                    // changes the separate media fader. Show the one moved.
                    int percent = mediaChanged ? media : master;
                    String channel = mediaChanged ? "media" : "master";
                    int step = Math.max(1, Math.min(30, Math.round(percent * 30f / 100f)));
                    volumePattern = percent == 0 ? null :
                            String.format(java.util.Locale.ROOT, "volume_step-%02d", step);
                    volumeStatus = channel + " " + percent + "%";
                    final long displayedGeneration = ++volumeGeneration;
                    queuePatternUpdate();
                    report();
                    if (volumePattern != null) {
                        Thread timeout = new Thread(() -> expireVolume(displayedGeneration),
                                "echo-plus2-volume-timeout");
                        timeout.setDaemon(true);
                        timeout.start();
                    }
                }
            });
        });
    }

    private void expireVolume(long displayedGeneration) {
        try {
            // The firmware's volume pattern itself goes dark after roughly
            // 1.4 seconds. Clear our ownership at the same time instead of
            // claiming a longer visible indicator.
            Thread.sleep(1400);
        } catch (InterruptedException ignored) {
            return;
        }
        synchronized (this) {
            if (!running || displayedGeneration != volumeGeneration || volumePattern == null) return;
            volumePattern = null;
            queuePatternUpdate();
        }
    }

    private void apply(long sequence, String wanted) {
        String old;
        synchronized (this) {
            if (!running || sequence != generation) return;
            old = ownedPattern;
            if (old == null ? wanted == null : old.equals(wanted)) return;
        }
        if (wanted == null) {
            String unset = command("--unset_pattern=" + old);
            synchronized (this) {
                if (old.equals(ownedPattern)) ownedPattern = null;
                ledStatus = "unset " + old + ": " + unset;
                report();
            }
            return;
        }

        // ledctrl keeps the old pattern on top when a new pattern is added.
        // Add the new one first, then remove the old one: the old LEDs remain
        // visible until the new fill is ready, avoiding a dark frame on each
        // Spotify slider step.
        String set = command("--set_pattern=" + wanted);
        if (!set.startsWith("exit=0")) {
            synchronized (this) {
                ledStatus = "set failed " + wanted + ": " + set;
                report();
            }
            return;
        }
        if (old != null) {
            String unset = command("--unset_pattern=" + old);
            if (!unset.startsWith("exit=0")) {
                command("--unset_pattern=" + wanted);
                synchronized (this) {
                    ledStatus = "replace failed " + old + " -> " + wanted + ": " + unset;
                    report();
                }
                return;
            }
        }
        String observed = command("--get_active_patterns");
        synchronized (this) {
            // Track only patterns that ledctrl accepted; never clear unrelated stock patterns.
            ownedPattern = wanted;
            ledStatus = "set " + wanted + ": " + set + "; " + observed;
            report();
            if (running && sequence == generation && ownedPattern != null &&
                    !"mics-off_on".equals(ownedPattern)) {
                final String pattern = ownedPattern;
                Thread timeout = new Thread(() -> expire(sequence, pattern), "echo-plus2-led-timeout");
                timeout.setDaemon(true);
                timeout.start();
            }
        }
    }

    private void expire(long sequence, String pattern) {
        try {
            Thread.sleep(30000);
        } catch (InterruptedException ignored) {
            return;
        }
        synchronized (this) {
            if (!running || sequence != generation || !pattern.equals(ownedPattern)) return;
            ledStatus = "30s safety timeout";
            worker.execute(() -> {
                String result = command("--unset_pattern=" + pattern);
                synchronized (EchoVoiceLedPlugin.this) {
                    if (pattern.equals(ownedPattern)) ownedPattern = null;
                    ledStatus = "expired " + pattern + ": " + result;
                    report();
                }
            });
        }
    }

    private static String command(String arg) {
        Process process = null;
        try {
            process = new ProcessBuilder(LEDCTRL, arg).redirectErrorStream(true).start();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (System.nanoTime() < deadline) {
                try {
                    int exit = process.exitValue();
                    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                    try (InputStream input = process.getInputStream()) {
                        byte[] buffer = new byte[256];
                        int n;
                        while ((n = input.read(buffer)) != -1 && bytes.size() < 256)
                            bytes.write(buffer, 0, Math.min(n, 256 - bytes.size()));
                    }
                    return "exit=" + exit + " " + bytes.toString("UTF-8").trim().replace('\n', ' ');
                } catch (IllegalThreadStateException stillRunning) {
                    Thread.sleep(40);
                }
            }
            return "timeout";
        } catch (Exception error) {
            return error.getClass().getSimpleName();
        } finally {
            if (process != null) process.destroy();
        }
    }

    private synchronized void report() {
        if (host != null) host.status("Voice: " + voiceState + " | LED: " + ledStatus +
                " | Beam: " + beamStatus + " | Volume: " + volumeStatus, false);
    }

    @Override public synchronized void onEvent(String event, Map<String, Object> payload) {
        if (!running) return;
        if ("ks.voice.state".equals(event)) {
            voiceEventSeen = true;
            updateState(String.valueOf(payload.get("state")));
        } else if ("ks.wakeword.state".equals(event)) {
            wakeEventSeen = true;
            updateMuted(Boolean.TRUE.equals(payload.get("muted")));
        } else if ("ks.device.volume".equals(event)) {
            readVolume(true);
        }
    }

    @Override public void configure(Map<String, Object> settings) {}

    @Override public void execute(String command, Map<String, Object> arguments) {
        throw new IllegalArgumentException("No direct actions");
    }

    @Override public synchronized void stop() {
        running = false;
        ++generation;
        host = null;
        if (worker != null) {
            worker.execute(() -> {
                String old;
                AspBeamObserver observer;
                synchronized (EchoVoiceLedPlugin.this) {
                    old = ownedPattern;
                    ownedPattern = null;
                    observer = beamObserver;
                    beamObserver = null;
                }
                if (observer != null) observer.close();
                if (old != null) command("--unset_pattern=" + old);
            });
            worker.shutdown();
        }
    }
}
