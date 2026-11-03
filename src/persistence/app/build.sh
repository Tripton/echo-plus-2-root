#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$sdk" ]]; then
    echo 'Set ANDROID_SDK_ROOT to an installed Android SDK.' >&2
    exit 2
fi
tools_version="${ANDROID_BUILD_TOOLS_VERSION:-36.0.0}"
ndk_version="${ANDROID_NDK_VERSION:-28.2.13676358}"
platform="${ANDROID_PLATFORM:-android-36}"
build_tools="$sdk/build-tools/$tools_version"
ndk="${ANDROID_NDK_ROOT:-$sdk/ndk/$ndk_version}"
android_jar="$sdk/platforms/$platform/android.jar"
case "$(uname -s)" in
    Darwin) host_tag=darwin-x86_64 ;;
    Linux) host_tag=linux-x86_64 ;;
    *) echo 'Unsupported host.' >&2; exit 2 ;;
esac
toolchain="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
for file in "$android_jar" "$build_tools/d8" "$build_tools/aapt2" \
            "$build_tools/apksigner" \
            "$toolchain/aarch64-linux-android23-clang" \
            "$toolchain/armv7a-linux-androideabi23-clang"; do
    if [[ ! -f "$file" ]]; then echo "Missing build tool: $file" >&2; exit 2; fi
done
for command in javac zip; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Missing command: $command" >&2; exit 2
    fi
done

out="${ECHO_APP_OUT:-$here/build}"
rm -rf "$out/classes"
mkdir -p "$out/classes" "$out/lib/arm64-v8a" "$out/lib/armeabi-v7a" "$out/assets"
rm -f "$out/classes.dex" "$out/binderprobe-unsigned.apk" "$out/binderprobe.apk"

javac -source 8 -target 8 -Xlint:-options -cp "$android_jar" \
    -d "$out/classes" "$here"/*.java
"$build_tools/d8" --min-api 23 --lib "$android_jar" --output "$out" \
    "$out"/classes/org/local/lidar/binderprobe/*.class
"$toolchain/aarch64-linux-android23-clang" \
    -shared -fPIC -Os -fvisibility=hidden -Wl,-z,noexecstack \
    -o "$out/lib/arm64-v8a/libbinderprobe.so" "$here/binderprobe.c"
"$toolchain/armv7a-linux-androideabi23-clang" \
    -shared -fPIC -Os -fvisibility=hidden -Wl,-z,noexecstack \
    -o "$out/lib/armeabi-v7a/libbinderprobe.so" "$here/binderprobe.c"
"$toolchain/aarch64-linux-android23-clang" \
    -O2 -static -Wl,-z,noexecstack \
    -o "$out/assets/probe_recvmsg64" "$here/recvmsg64_control.c"
"$toolchain/aarch64-linux-android23-clang" \
    -O2 -static -Wl,-z,noexecstack \
    -o "$out/assets/core_crash64" "$here/core_crash64.c"
"$build_tools/aapt2" link -o "$out/binderprobe-unsigned.apk" \
    --manifest "$here/AndroidManifest.xml" -I "$android_jar" \
    --min-sdk-version 23 --target-sdk-version 23
# aapt2 uses the ZIP epoch. Give our entries the same fixed timestamp so
# identical sources produce identical unsigned APKs in different directories.
TZ=UTC touch -t 198001010000 "$out/classes.dex" \
    "$out/lib/arm64-v8a/libbinderprobe.so" \
    "$out/lib/armeabi-v7a/libbinderprobe.so" \
    "$out/assets/probe_recvmsg64" "$out/assets/core_crash64"
(
    cd "$out"
    zip -X -q binderprobe-unsigned.apk classes.dex \
        lib/arm64-v8a/libbinderprobe.so lib/armeabi-v7a/libbinderprobe.so \
        assets/probe_recvmsg64 assets/core_crash64
)

if [[ -n "${APK_KEYSTORE:-}" ]]; then
    for name in APK_KEY_ALIAS APK_KS_PASS_FILE APK_KEY_PASS_FILE; do
        if [[ -z "${!name:-}" ]]; then echo "Set $name for APK signing." >&2; exit 2; fi
    done
    "$build_tools/apksigner" sign --ks "$APK_KEYSTORE" \
        --ks-key-alias "$APK_KEY_ALIAS" \
        --ks-pass "file:$APK_KS_PASS_FILE" --key-pass "file:$APK_KEY_PASS_FILE" \
        --v1-signing-enabled true --v2-signing-enabled false \
        --out "$out/binderprobe.apk" "$out/binderprobe-unsigned.apk"
    "$build_tools/apksigner" verify --min-sdk-version 23 "$out/binderprobe.apk"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$out/binderprobe.apk"
    else
        sha256sum "$out/binderprobe.apk"
    fi
else
    echo 'BUILD_UNSIGNED_OK: Set APK_KEYSTORE and password files to sign an installable APK.'
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$out/binderprobe-unsigned.apk"
    else
        sha256sum "$out/binderprobe-unsigned.apk"
    fi
fi
