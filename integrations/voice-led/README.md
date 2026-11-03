# Echo Plus 2 voice LED plugin

This optional [Kiosk Satellite](https://github.com/jxlarrea/kiosk-satellite) plugin uses the device's existing LED controller and reports voice, mute, volume, and beam-direction states. The tested unit has 12 LED segments. Install the [ASR microphone plugin](../asr-mic/README.md) as well to select the audio path that produced native beam events on Kiosk 2026.10.45. Direction is shown only when the stock audio processor emits a valid beam index; otherwise the listening pattern is not directional.

From the repository root, fetch the [Kiosk Satellite plugin SDK](https://github.com/jxlarrea/kiosk-satellite-plugins) and build with Android platform 36. These commands use the tested macOS SDK location:

```sh
mkdir -p local/tools
git clone --filter=blob:none https://github.com/jxlarrea/kiosk-satellite-plugins.git local/tools/kiosk-satellite-plugins
git -C local/tools/kiosk-satellite-plugins checkout c7a95943a8922b6fea4b42cf0e5cdb281421e305
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools python3 \
  local/tools/kiosk-satellite-plugins/tools/build.py \
  integrations/voice-led --android-platform 36
```

The build creates `integrations/voice-led/dist/echo-plus2-voice-led-0.1.7.zip`. Open Kiosk's browser interface at the address printed by `KIOSK_SETUP_READY`. Under **Settings → Plugin Manager**, switch on **Enable Plugins**. Under **Developer Tools → Install from ZIP**, select that ZIP, review it, choose **Trust and install**, then enable the plugin in its entry row. This is the [documented local plugin flow](https://github.com/jxlarrea/kiosk-satellite-plugins/blob/main/docs/installing-plugins.md#developer-tools).

The SDK and Kiosk Satellite APK are separate dependencies. The source here is covered by the repository's [Apache-2.0 license](../../LICENSE). Distribution with Kiosk Satellite also depends on its [plugin exception](https://github.com/jxlarrea/kiosk-satellite/blob/main/PLUGIN-EXCEPTION.md).
