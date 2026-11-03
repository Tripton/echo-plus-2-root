# Echo Plus 2 ASR microphone plugin

Kiosk Satellite normally opens Android's microphone source 1 on this device. This plugin selects source 6 (`VOICE_RECOGNITION`) for Kiosk's **existing** recorder so the stock audio signal processor can emit the beam index used by the [Voice LED plugin](../voice-led/README.md). It does not open a second recorder or read or store microphone audio.

The plugin checks Kiosk's package and the exact recorder class, field, constructor, and value layout at runtime. It briefly mutes and unmutes the wake word to make Kiosk reopen its recorder, then requires Android to report one active source-6 recording and no source-1 recording. If that check fails, it restores Kiosk's previous recorder preference. A compatible Kiosk update is not rejected solely because its version or APK hash changed. This does **not** guarantee that every future Kiosk version is compatible.

Version 0.1.1 was tested on the Echo Plus 2 with Kiosk Satellite 2026.10.45. The live test observed source 6, changing native beam indices, matching LED rotation in 33 of 35 listening samples, and spoken answers from two physical directions. The two unmatched samples occurred around asynchronous index changes. Physical angle calibration was not measured.

Build it from the repository root using the [Kiosk Satellite plugin SDK](https://github.com/jxlarrea/kiosk-satellite-plugins) and Android platform 36:

```sh
mkdir -p local/tools
git clone --filter=blob:none https://github.com/jxlarrea/kiosk-satellite-plugins.git local/tools/kiosk-satellite-plugins
git -C local/tools/kiosk-satellite-plugins checkout c7a95943a8922b6fea4b42cf0e5cdb281421e305
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools python3 \
  local/tools/kiosk-satellite-plugins/tools/build.py \
  integrations/asr-mic --android-platform 36
```

Install the resulting `integrations/asr-mic/dist/echo-plus2-asr-mic-0.1.1.zip` in Kiosk's **Settings → Plugin Manager → Developer Tools → Install from ZIP**, then enable it. Install the Voice LED plugin as well. Its `beam_index` reading should become numeric while the wake word is actively listening. If it remains null, check this plugin's status and Android's recording permission before changing LED patterns.

The source is under [Apache-2.0](../../LICENSE). Distribution with Kiosk Satellite also depends on its [plugin exception](https://github.com/jxlarrea/kiosk-satellite/blob/main/PLUGIN-EXCEPTION.md).
