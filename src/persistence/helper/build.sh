#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${ECHO_HELPER_OUT:-$here/build}"
sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk" ]]; then
    echo 'Set ANDROID_SDK_ROOT to an installed Android SDK.' >&2
    exit 2
fi
ndk_version="${ANDROID_NDK_VERSION:-28.2.13676358}"
ndk="${ANDROID_NDK_ROOT:-$sdk/ndk/$ndk_version}"
case "$(uname -s)" in
    Darwin) host_tag=darwin-x86_64 ;;
    Linux) host_tag=linux-x86_64 ;;
    *) echo 'Unsupported host. Set up the NDK toolchain manually.' >&2; exit 2 ;;
esac
cc="$ndk/toolchains/llvm/prebuilt/$host_tag/bin/aarch64-linux-android23-clang"
if [[ ! -f "$cc" ]]; then echo "Missing compiler: $cc" >&2; exit 2; fi
mkdir -p "$out"
"$cc" -static -O2 -std=c11 -Wall -Wextra -Werror -Wl,-z,noexecstack \
    -DMIC_KEEPER_RUNCON_CHILD -o "$out/kiosk_mic_keeper" \
    "$here/kiosk_mic_keeper.c"
"$cc" -static -O2 -std=c11 -Wall -Wextra -Werror -Wl,-z,noexecstack \
    -o "$out/key_forwarder" "$here/key_forwarder.c"
if command -v shasum >/dev/null 2>&1; then
    mic_sha="$(shasum -a 256 "$out/kiosk_mic_keeper" | cut -d ' ' -f 1)"
    button_sha="$(shasum -a 256 "$out/key_forwarder" | cut -d ' ' -f 1)"
else
    mic_sha="$(sha256sum "$out/kiosk_mic_keeper" | cut -d ' ' -f 1)"
    button_sha="$(sha256sum "$out/key_forwarder" | cut -d ' ' -f 1)"
fi
mic_size="$(wc -c < "$out/kiosk_mic_keeper" | tr -d '[:space:]')"
button_size="$(wc -c < "$out/key_forwarder" | tr -d '[:space:]')"
printf '{"mic":{"sha256":"%s","bytes":%s},"buttons":{"sha256":"%s","bytes":%s}}\n' \
    "$mic_sha" "$mic_size" "$button_sha" "$button_size" > "$out/workers.json.tmp"
mv "$out/workers.json.tmp" "$out/workers.json"
"$cc" -static -O2 -Wall -Wextra -Werror -Wl,-z,noexecstack \
    "-DMIC_HELPER_SHA256=\"$mic_sha\"" "-DMIC_HELPER_SIZE=$mic_size" \
    "-DBUTTON_HELPER_SHA256=\"$button_sha\"" "-DBUTTON_HELPER_SIZE=$button_size" \
    -o "$out/core_helper64" "$here/core_helper64.c" "$here/sha256.c"
"$cc" -static -O2 -Wall -Wextra -Werror -Wl,-z,noexecstack \
    -o "$out/usb_root_client" "$here/usb_root_client.c"
if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$out/core_helper64" "$out/usb_root_client" \
        "$out/kiosk_mic_keeper" "$out/key_forwarder"
else
    sha256sum "$out/core_helper64" "$out/usb_root_client" \
        "$out/kiosk_mic_keeper" "$out/key_forwarder"
fi
