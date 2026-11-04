# Changelog

## 2026-11-04

- Updated the tested Echo Plus 2 from Kiosk Satellite 2026.10.45 to
  [2026.11.5](https://github.com/jxlarrea/kiosk-satellite/releases/tag/2026.11.5).
  The app and Home Assistant connection resumed with existing settings.
- Added the optional [temperature plugin](integrations/temperature/README.md).
  It reads the stock `ambient_v_thermal` estimate once per minute and exposes
  it as a Home Assistant temperature entity. It does not require a new root
  helper or firmware change.
