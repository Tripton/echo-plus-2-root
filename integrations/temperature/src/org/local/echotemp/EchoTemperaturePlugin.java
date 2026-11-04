// SPDX-License-Identifier: Apache-2.0
package org.local.echotemp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import me.jxl.kiosk.plugins.KioskPlugin;
import me.jxl.kiosk.plugins.PluginHost;

/** Read the stock ambient-temperature estimate without changing device state. */
public final class EchoTemperaturePlugin implements KioskPlugin {
    private static final File THERMAL_ZONES = new File("/sys/class/thermal");
    private static final String AMBIENT_TYPE = "ambient_v_thermal";
    private static final long POLL_SECONDS = 60;

    private volatile boolean running;
    private PluginHost host;
    private ScheduledExecutorService worker;

    @Override public void start(PluginHost pluginHost, Map<String, Object> settings) {
        host = pluginHost;
        running = true;

        host.publishSensor("room_temperature", "Room temperature", metadata(), null);

        worker = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "echo-plus2-temperature");
            thread.setDaemon(true);
            return thread;
        });
        worker.scheduleWithFixedDelay(this::publishTemperature, 0, POLL_SECONDS, TimeUnit.SECONDS);
    }

    private void publishTemperature() {
        Double temperature = null;
        try {
            File[] zones = THERMAL_ZONES.listFiles();
            if (zones != null) {
                for (File zone : zones) {
                    if (!zone.getName().matches("thermal_zone[0-9]+")) continue;
                    if (!AMBIENT_TYPE.equals(readLine(new File(zone, "type")))) continue;
                    String raw = readLine(new File(zone, "temp"));
                    if (raw == null) break;
                    double celsius = Double.parseDouble(raw.trim()) / 1000.0;
                    if (Double.isFinite(celsius) && celsius >= -50 && celsius <= 100) {
                        temperature = celsius;
                    }
                    break;
                }
            }
        } catch (NumberFormatException ignored) {
            // A malformed value is published as unavailable, never as zero.
        }
        if (running) {
            host.publishSensor("room_temperature", "Room temperature", metadata(), temperature);
            host.status(temperature == null ? "Temperature unavailable" : "Reading stock ambient estimate",
                    temperature == null);
        }
    }

    private static String readLine(File file) {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            return reader.readLine();
        } catch (IOException ignored) {
            return null;
        }
    }

    private static Map<String, Object> metadata() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("unit", "°C");
        result.put("deviceClass", "temperature");
        result.put("stateClass", "measurement");
        result.put("accuracyDecimals", 1);
        return result;
    }

    @Override public void configure(Map<String, Object> settings) {}
    @Override public void execute(String command, Map<String, Object> arguments) {}
    @Override public void onEvent(String event, Map<String, Object> payload) {}

    @Override public void stop() {
        running = false;
        if (worker != null) worker.shutdownNow();
        worker = null;
    }
}
