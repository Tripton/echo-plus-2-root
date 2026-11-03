# Echo Plus 2 buttons plugin

This optional [Kiosk Satellite](https://github.com/jxlarrea/kiosk-satellite) plugin receives the Plus 2's Action and Mute events from the local button worker. It forwards only those two keys to Kiosk's existing button handler. The `configure` step installs the worker when `kiosk.install = true`; enable this plugin to connect it to Kiosk.

From the repository root, fetch the [Kiosk Satellite plugin SDK](https://github.com/jxlarrea/kiosk-satellite-plugins) if you have not already done so:

```sh
mkdir -p local/tools
git clone --filter=blob:none https://github.com/jxlarrea/kiosk-satellite-plugins.git local/tools/kiosk-satellite-plugins
git -C local/tools/kiosk-satellite-plugins checkout c7a95943a8922b6fea4b42cf0e5cdb281421e305
```

Build the plugin with Android platform 36. The SDK path below is the tested macOS installation:

```sh
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools python3 \
  local/tools/kiosk-satellite-plugins/tools/build.py \
  integrations/buttons --android-platform 36
```

The build creates `integrations/buttons/dist/echo-plus2-buttons-0.1.2.zip`. Open Kiosk's browser interface at the address printed by `KIOSK_SETUP_READY`. Under **Settings → Plugin Manager**, switch on **Enable Plugins**. Under **Developer Tools → Install from ZIP**, select the ZIP, review it, choose **Trust and install**, then enable the plugin in its entry row. Action and Mute must be configured in Kiosk's button settings. This follows the SDK's [local plugin installation guide](https://github.com/jxlarrea/kiosk-satellite-plugins/blob/main/docs/installing-plugins.md#developer-tools).

The source is covered by the repository's [Apache-2.0 license](../../LICENSE). Distribution with Kiosk Satellite also depends on its [plugin exception](https://github.com/jxlarrea/kiosk-satellite/blob/main/PLUGIN-EXCEPTION.md).
