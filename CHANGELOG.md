# Changelog

## 2026-11-11

- Refactored the boot and kernel stages for multiple firmware builds and either A or B slot. Added offline-checked profiles for `NS6536/2509N`, `NS6541/2965N` and `NS65741/8149N`. Device tests are still pending.
- Added `diagnose` to collect early boot images from unsupported firmware for manual offset analysis.

## 2026-11-10

- Use Kamakiri2 for Linux `dump` and `boot` because Linux rejected the older Kamakiri USB request.
- Save twice-read firmware data before build-specific checks, so unsupported builds yield captures for locating offsets. A different preloader still stops further eMMC reads.
- Confirmed a live read-only `dump` in an Arch Linux ARM UTM VM. All seven captures matched the independent macOS dump.
- Allowed ten root attempts across separate boots after one stalled start exhausted the previous single attempt. A skipped attempt recovered on the next boot.
- Added `recover-root` for exhausted attempts.

## 2026-11-05

- Added local WiFi access to Kiosk's web interface.
- Documented optional screenless Kiosk updates, tested through 2026.11.7.

## 2026-11-04

- Updated the tested Echo Plus 2 from Kiosk Satellite 2026.10.45 to
  [2026.11.5](https://github.com/jxlarrea/kiosk-satellite/releases/tag/2026.11.5).
  The app and Home Assistant connection resumed with existing settings.
- Added the optional [temperature plugin](integrations/temperature/README.md).
  It reads the stock `ambient_v_thermal` estimate once per minute and exposes
  it as a Home Assistant temperature entity. It does not require a new root
  helper or firmware change.
