// SPDX-License-Identifier: Apache-2.0
package org.local.echobuttons;

import android.net.Credentials;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.KeyEvent;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Map;
import me.jxl.kiosk.plugins.KioskPlugin;
import me.jxl.kiosk.plugins.PluginHost;

/** A narrow input bridge for the stock Plus 2 key layout.
 *
 * The stock gpio-keys.kl maps Linux KEY_HELP to Android BUTTON_MODE (110),
 * whereas Kiosk Satellite's button handler expects HELP (259). This bridge
 * receives only A or M from a root/shell peer reading the two GPIO devices
 * and passes a normal down/up pair to Kiosk's existing button logic. It
 * never accepts a command string, address, path, or key code from the peer.
 */
public final class EchoButtonsPlugin implements KioskPlugin {
    private static final String SOCKET = "echo_plus2_buttons_v1";
    private final Handler main = new Handler(Looper.getMainLooper());
    private volatile boolean running;
    private LocalServerSocket server;
    private Thread listener;
    private PluginHost host;
    private Method onKey;
    private int accepted;
    private String last = "waiting";

    @Override public synchronized void start(PluginHost newHost, Map<String, Object> settings)
            throws Exception {
        Class<?> type = Class.forName("me.jxl.kiosk_satellite.HardwareKeys", true,
                getClass().getClassLoader());
        onKey = type.getMethod("onKey", KeyEvent.class);
        // In the release APK R8 turns the Kotlin singleton into a static
        // class. Check the exact version's active key map before accepting
        // any peer: both default buttons must already be configured.
        Object configured = type.getField("wanted").get(null);
        if (!(configured instanceof Map) ||
                !((Map<?, ?>) configured).containsKey(KeyEvent.KEYCODE_HELP) ||
                !((Map<?, ?>) configured).containsKey(KeyEvent.KEYCODE_MUTE)) {
            throw new IllegalStateException("Kiosk default buttons are not configured");
        }
        host = newHost;
        server = new LocalServerSocket(SOCKET);
        running = true;
        listener = new Thread(this::listen, "echo-plus2-button-listener");
        listener.setDaemon(true);
        listener.start();
        report();
    }

    private void listen() {
        while (running) {
            try (LocalSocket client = server.accept()) {
                Credentials peer = client.getPeerCredentials();
                int uid = peer.getUid();
                if (uid != 0 && uid != 2000) continue;
                client.setSoTimeout(1000);
                int key = client.getInputStream().read();
                if (key != 'A' && key != 'M') continue;
                if (client.getInputStream().read() != -1) continue;
                main.post(() -> press(key == 'A' ? KeyEvent.KEYCODE_HELP : KeyEvent.KEYCODE_MUTE));
            } catch (IOException error) {
                if (running) {
                    last = "socket error: " + error.getClass().getSimpleName();
                    report();
                }
            }
        }
    }

    private void press(int code) {
        if (!running) return;
        try {
            long at = SystemClock.uptimeMillis();
            Object down = onKey.invoke(null,
                    new KeyEvent(at, at, KeyEvent.ACTION_DOWN, code, 0));
            Object up = onKey.invoke(null,
                    new KeyEvent(at, at + 1, KeyEvent.ACTION_UP, code, 0));
            accepted++;
            last = (code == KeyEvent.KEYCODE_HELP ? "action" : "microphone")
                    + " down=" + down + " up=" + up;
            report();
        } catch (Exception error) {
            last = "dispatch error: " + error.getClass().getSimpleName();
            report();
        }
    }

    private synchronized void report() {
        if (host != null) host.status("Buttons: " + accepted + " | " + last, false);
    }

    @Override public void configure(Map<String, Object> settings) {}

    @Override public void execute(String command, Map<String, Object> arguments) {
        throw new IllegalArgumentException("No direct actions");
    }

    @Override public void onEvent(String event, Map<String, Object> payload) {}

    @Override public synchronized void stop() throws Exception {
        running = false;
        host = null;
        if (server != null) server.close();
        if (listener != null) listener.interrupt();
    }
}
