# Echo Plus 2 temperature plugin

This optional Kiosk Satellite plugin publishes the Echo Plus 2's stock
`ambient_v_thermal` estimate as **Room temperature**. It reads the value once
per minute from `/sys/class/thermal`; it does not use the CPU or case
temperature. The value is an estimate, not a calibrated room thermometer.

From the repository root, get the [Kiosk Satellite plugin SDK](https://github.com/jxlarrea/kiosk-satellite-plugins)
if you do not already have it:

```sh
mkdir -p local/tools
git clone --filter=blob:none https://github.com/jxlarrea/kiosk-satellite-plugins.git local/tools/kiosk-satellite-plugins
git -C local/tools/kiosk-satellite-plugins checkout c7a95943a8922b6fea4b42cf0e5cdb281421e305
```

Build with Android platform 36. This SDK location is the tested macOS path:

```sh
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools python3 \
  local/tools/kiosk-satellite-plugins/tools/build.py \
  integrations/temperature --android-platform 36
```

In Kiosk, open **Settings → Plugin Manager → Developer Tools → Install from ZIP**,
select `integrations/temperature/dist/echo-plus2-temperature-0.1.0.zip`, and
enable the plugin. Enable ESPHome and native plugin entities in Kiosk to see
the reading on the Echo Plus 2 device in Home Assistant.

On the tested Echo Plus 2, the stock interface read 19.463 °C. Kiosk then
reported 19.419 °C and Home Assistant displayed 19.4 °C. These observations
confirm the data path, not its accuracy against a reference thermometer.

The source is covered by the repository's [Apache-2.0 license](../../LICENSE).
Distribution with Kiosk Satellite also depends on its
[plugin exception](https://github.com/jxlarrea/kiosk-satellite/blob/main/PLUGIN-EXCEPTION.md).
