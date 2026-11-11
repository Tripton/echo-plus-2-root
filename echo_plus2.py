#!/usr/bin/env python3
"""Root an Echo Plus 2 using exact-image, guarded firmware stages."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

import configure_gate


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src/bootstrap"))
from firmware_profiles import NS6575_8338N, by_name
# Everything created by this guide stays in one Git-ignored tree. Source and
# captures can then travel together without adding device data to a commit.
LOCAL = ROOT / "local"
DEVICE = LOCAL / "device"
BOOT_BUILD = LOCAL / "build/bootstrap"
STOCK_BUILD = LOCAL / "build/stock-transition"
HELPER_BUILD = LOCAL / "build/helper"
APP_BUILD = LOCAL / "build/app"
MTK_ROOT = LOCAL / "tools/mtkclient"
# These are compatibility pins for the one measured firmware and upstream
# tool revision, not user settings. Stop on a mismatch before writing /data.
MTKCLIENT_COMMIT = "7cb40e727727dfe3faa065eefb29b16ed29bbdf1"
FULL_CAPS = "0000003fffffffff"
START = time.monotonic()


def phase(label: str) -> None:
    print(f"\n[{time.strftime('%H:%M:%S')} +{time.monotonic() - START:.0f}s] {label}", flush=True)


def call(*parts: object, env: dict[str, str] | None = None, capture: bool = False) -> str:
    command = [str(part) for part in parts]
    print("+", shlex.join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None,
                            check=True)
    return result.stdout or ""


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_dir(path: Path) -> Path:
    logical = path.expanduser().absolute()
    if DEVICE.is_symlink():
        raise RuntimeError("local/device itself must not be a symlink")
    if logical.is_relative_to(ROOT) and logical != DEVICE:
        raise RuntimeError("Private files inside this repository belong only in local/device")
    if LOCAL.is_symlink():
        target = LOCAL.resolve(strict=True)
        target_info = target.stat()
        if (not target.is_dir() or target_info.st_uid != os.getuid()
                or (target_info.st_mode & 0o777) != 0o700):
            raise RuntimeError("The local symlink target must be your private mode-0700 directory")
        if logical == DEVICE and logical.resolve() != target / "device":
            raise RuntimeError("local/device resolves outside the selected local directory")
    if logical == DEVICE:
        # Ignore both an ordinary local directory and the symlink itself.
        call("git", "check-ignore", "-q", "local", capture=True)
    path = logical.resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    permissions = path.stat()
    if permissions.st_uid != os.getuid() or (permissions.st_mode & 0o777) != 0o700:
        raise RuntimeError("Private capture directory must be owned by you and mode 0700")
    return path


def state_path(private: Path) -> Path:
    return private / "setup-state.json"


def read_state(private: Path) -> dict[str, str]:
    path = state_path(private)
    return json.loads(path.read_text()) if path.exists() else {}


def selected_firmware(state: dict[str, str]):
    """Resolve the saved exact image and its independent physical slot."""
    marker = state.get("firmware_profile", "NS6575-8338N a")
    parts = marker.split()
    if len(parts) == 1 and parts[0] == NS6575_8338N.name:
        parts.append("a")  # Private state from the original single-slot guide.
    if len(parts) != 2 or parts[1] not in ("a", "b"):
        raise RuntimeError("Saved firmware profile or slot is malformed; rebuild from dump")
    return by_name(parts[0]), parts[1]


def save_state(private: Path, state: dict[str, str]) -> None:
    path = state_path(private)
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(state, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def detect_sdk() -> Path:
    candidates = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME"),
                  str(Path.home() / "Library/Android/sdk"),
                  str(Path.home() / "Android/Sdk"),
                  "/opt/homebrew/share/android-commandlinetools"]
    for candidate in candidates:
        if candidate and (Path(candidate) / "build-tools/36.0.0/apksigner").is_file():
            return Path(candidate).expanduser().resolve()
    raise RuntimeError("Android SDK Build Tools 36.0.0 missing; set ANDROID_SDK_ROOT")


def use_sdk_platform_tools(sdk: Path) -> None:
    platform_tools = sdk / "platform-tools"
    for name in ("adb", "fastboot"):
        if not (platform_tools / name).is_file():
            raise RuntimeError(f"Missing Android SDK Platform Tool: {platform_tools / name}")
    # Every device command in this guided run resolves to the same SDK, even
    # when platform-tools was not added to the user's login-shell PATH.
    os.environ["PATH"] = str(platform_tools) + os.pathsep + os.environ.get("PATH", "")


def detect_llvm(name: str, package: str) -> Path:
    candidates: list[Path] = []
    if platform.system() == "Darwin" and shutil.which("brew"):
        try:
            prefix = subprocess.run(["brew", "--prefix", package], text=True,
                                    capture_output=True, check=True).stdout.strip()
            candidates.append(Path(prefix) / "bin" / name)
        except subprocess.CalledProcessError:
            pass
    found = shutil.which(name)
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file() and "23.1.3" in call(candidate, "--version", capture=True):
            # ld.lld may be a symlink to the generic `lld` executable. Its
            # basename selects the Unix linker driver, so preserve the alias.
            return candidate.absolute()
    raise RuntimeError(f"{name} 23.1.3 missing; install the pinned LLVM/LLD toolchain")


def host(args: argparse.Namespace, *, android: bool) -> dict[str, object]:
    mtk = args.mtkclient_root.expanduser().resolve()
    python = mtk / ".venv/bin/python"
    if not python.is_file() or not (mtk / "mtk.py").is_file():
        raise RuntimeError("Pinned MTKClient is missing from local/tools/mtkclient; follow the README setup commands")
    if call("git", "-C", mtk, "rev-parse", "HEAD", capture=True).strip() != MTKCLIENT_COMMIT:
        raise RuntimeError("MTKClient checkout differs from the pinned revision in README.md")
    stage1 = mtk / "mtkclient/payloads/generic_stage1_payload.bin"
    if not stage1.is_file():
        raise RuntimeError(f"Missing MTKClient stage 1: {stage1}")
    clang = detect_llvm("clang", "llvm")
    ld = detect_llvm("ld.lld", "lld")
    objcopy = detect_llvm("llvm-objcopy", "llvm")
    result: dict[str, object] = {"mtk": mtk, "python": python, "stage1": stage1,
                                 "clang": clang, "ld": ld, "objcopy": objcopy}
    if android:
        sdk = detect_sdk()
        use_sdk_platform_tools(sdk)
        tag = {"Darwin": "darwin-x86_64", "Linux": "linux-x86_64"}.get(platform.system())
        if not tag:
            raise RuntimeError("Only macOS and Linux toolchains are supported")
        ndk_cc = sdk / f"ndk/28.2.13676358/toolchains/llvm/prebuilt/{tag}/bin/aarch64-linux-android23-clang"
        for path in (ndk_cc, sdk / "platforms/android-36/android.jar",
                     sdk / "build-tools/36.0.0/aapt",
                     sdk / "build-tools/36.0.0/apksigner"):
            if not path.is_file():
                raise RuntimeError(f"Missing Android SDK component: {path}")
        for name in ("javac", "keytool", "zip", "adb", "fastboot"):
            if not shutil.which(name):
                raise RuntimeError(f"Missing host command: {name}")
        result.update(sdk=sdk, ndk_cc=ndk_cc)
    return result


def prompt_cycle() -> None:
    print("Keep Echo power disconnected and USB data connected.", flush=True)
    print("Wait for WAIT_FOR_BOOTROM. Then hold Action (the dot button), reconnect power, and release Action at RELEASE_ACTION_NOW.", flush=True)


def dump(args: argparse.Namespace, private: Path, tools: dict[str, object]) -> None:
    state = read_state(private)
    if args.reuse:
        phase("Checking the saved device dump")
        call(tools["python"], ROOT / "src/bootstrap/capture.py",
             "--mtkclient-root", tools["mtk"], "--output-dir", private,
             "--verify-captures")
        if not state.get("meid_sha256"):
            report = json.loads((private / "capture-report.json").read_text())
            meid_hash = report.get("meid_sha256", "")
            if not re.fullmatch(r"[0-9a-f]{64}", meid_hash):
                raise RuntimeError("Verified capture has no usable device hash")
            state["meid_sha256"] = meid_hash
            save_state(private, state)
    else:
        prompt_cycle()
        phase("Reading and checking this Echo's firmware")
        command = [tools["python"], ROOT / "src/bootstrap/capture.py",
                   "--mtkclient-root", tools["mtk"], "--output-dir", private]
        if state.get("meid_sha256"):
            command.extend(("--target-meid-sha256", state["meid_sha256"]))
        call(*command, "--run")
        report = json.loads((private / "capture-report.json").read_text())
        # Capture reports only a hash of the chip's ME_ID. The RAM runner uses
        # that hash to reject a different Echo without storing its raw ID here.
        meid_hash = report.get("meid_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", meid_hash):
            raise RuntimeError("Verified capture did not record this Echo's device hash")
        if state.get("meid_sha256") and state["meid_sha256"] != meid_hash:
            raise RuntimeError("Capture belongs to another Echo")
        state["meid_sha256"] = meid_hash
        save_state(private, state)
    phase("Building the temporary RAM image")
    call(tools["python"], ROOT / "src/bootstrap/build.py",
         "--preloader", private / "preloader-from-sram.bin",
         "--lk-a", private / "lk_a.bin", "--lk-b", private / "lk_b.bin",
         "--boot-a", private / "boot_a-live.bin",
         "--boot-b", private / "boot_b-live.bin",
         "--misc", private / "misc-window.bin", "--stage1", tools["stage1"],
         "--clang", tools["clang"], "--ld", tools["ld"],
         "--objcopy", tools["objcopy"], "--out", BOOT_BUILD)
    profile = (BOOT_BUILD / "firmware-profile.txt").read_text().strip()
    state["firmware_profile"] = profile
    state["capture_ready"] = "yes"
    save_state(private, state)
    if profile != "NS6575-8338N a":
        print(f"EXPERIMENTAL_RAM_IMAGE_READY: {profile} has passed offline checks but no device boot test", flush=True)
        print("Next: python3 echo_plus2.py boot", flush=True)
    else:
        print("DUMP_AND_RAM_IMAGE_READY. Next: python3 echo_plus2.py boot", flush=True)


def diagnose_firmware(private: Path, tools: dict[str, object]) -> None:
    output = Path(tempfile.mkdtemp(prefix="diagnostic-", dir=private))
    prompt_cycle()
    phase("Reading this Echo's firmware for offset analysis")
    call(tools["python"], ROOT / "src/bootstrap/capture.py",
         "--mtkclient-root", tools["mtk"], "--output-dir", output,
         "--diagnose", "--run")
    print(f"DIAGNOSTIC_FILES_READY: {output}", flush=True)


def adb(*parts: str, capture_output: bool = True) -> str:
    return call("adb", "-d", *parts, capture=capture_output)


def usb_serial_from_cmdline() -> str:
    cmdline = adb("shell", "cat /proc/cmdline")
    match = re.search(r"(?:^|\s)androidboot\.serialno=([A-Z0-9]{12,24})(?=\s|$)", cmdline)
    if not match or "androidboot.hardware=mt8167" not in cmdline.split():
        raise RuntimeError("USB Echo kernel identity is missing or differs")
    serial = match.group(1)
    reported = adb("get-serialno").strip()
    if reported and reported != serial:
        raise RuntimeError("USB ADB and kernel serials differ")
    return serial


def wait_recovery(expected_serial: str | None) -> str:
    deadline = time.monotonic() + 150
    continued_fastboot = False
    fastboot_serial = None
    while time.monotonic() < deadline:
        result = subprocess.run(["adb", "-d", "get-state"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == "recovery":
            serial = usb_serial_from_cmdline()
            if (expected_serial and serial != expected_serial) or (
                    fastboot_serial and serial != fastboot_serial):
                raise RuntimeError("Recovery serial differs from the selected Echo")
            status = adb("shell", "cat /proc/self/status")
            identity = adb("shell", "id")
            if (not re.fullmatch(r"[A-Z0-9]{12,24}", serial) or
                    "uid=0(root)" not in identity or
                    f"CapEff:\t{FULL_CAPS}" not in status or
                    f"CapBnd:\t{FULL_CAPS}" not in status):
                raise RuntimeError("USB recovery identity or full capabilities differ")
            return serial
        if not continued_fastboot and shutil.which("fastboot"):
            found = subprocess.run(["fastboot", "devices"], capture_output=True, text=True,
                                   timeout=5, check=True).stdout.splitlines()
            devices = [line.split()[0] for line in found if line.split()]
            if len(devices) > 1:
                raise RuntimeError("More than one Fastboot device is connected")
            if len(devices) == 1:
                serial = devices[0]
                if expected_serial and serial != expected_serial:
                    raise RuntimeError("Fastboot serial differs from the saved Echo")
                if not sys.stdin.isatty():
                    raise RuntimeError("Fastboot appeared; release Action and continue it manually")
                confirmation = input(
                    f"Fastboot device {serial} appeared. Release Action. "
                    "If this is your Echo, type its full serial to continue: ").strip()
                if confirmation != serial:
                    raise RuntimeError("Fastboot target was not confirmed")
                fastboot_serial = serial
                call("fastboot", "-s", serial, "continue")
                continued_fastboot = True
        time.sleep(2)
    raise RuntimeError("Full-capability USB recovery did not appear within 150 seconds")


def save_recovery_file(remote: str, local: Path) -> None:
    result = subprocess.run(["adb", "-d", "exec-out", "cat", remote],
                            capture_output=True, check=True)
    if local.exists() and local.read_bytes() != result.stdout:
        raise RuntimeError(f"Existing private capture differs: {local}")
    local.write_bytes(result.stdout)
    print(f"Captured {remote}: {len(result.stdout)} bytes, sha256={sha(local)}", flush=True)


def boot(private: Path, tools: dict[str, object], *, resume: bool = False) -> None:
    state = read_state(private)
    if state.get("capture_ready") != "yes" or not state.get("meid_sha256"):
        raise RuntimeError("Run python3 echo_plus2.py dump before boot")
    built_marker = BOOT_BUILD / "firmware-profile.txt"
    expected_profile = state.get("firmware_profile", "NS6575-8338N")
    if built_marker.exists() and built_marker.read_text() != expected_profile + "\n":
        raise RuntimeError("Saved Echo profile differs from the built RAM image; rebuild from its dump")
    phase("Checking the RAM image before touching the Echo")
    runner = [tools["python"], ROOT / "src/bootstrap/run.py",
              "--mtkclient-root", tools["mtk"], "--stage1", tools["stage1"],
              "--target-meid-sha256", state["meid_sha256"],
              "--built-dir", BOOT_BUILD]
    call(*runner)
    use_sdk_platform_tools(detect_sdk())
    if resume:
        phase("Resuming the running USB recovery after an interrupted guide")
    else:
        prompt_cycle()
        phase("Starting temporary root from RAM")
        call(*runner, "--run")
    serial = wait_recovery(state.get("usb_serial"))
    if state.get("usb_serial") and state["usb_serial"] != serial:
        raise RuntimeError("Recovery serial differs from the saved target")
    state["usb_serial"] = serial
    state["recovery_boot_id"] = adb("shell", "cat /proc/sys/kernel/random/boot_id").strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", state["recovery_boot_id"]):
        raise RuntimeError("Could not identify this temporary recovery boot")
    save_state(private, state)
    if expected_profile not in ("NS6575-8338N", "NS6575-8338N a"):
        print("EXPERIMENTAL_RAM_RECOVERY_READY. Next: persist to test cold-boot root", flush=True)
    else:
        print("TEMPORARY_ROOT_READY. Next: persist for initial setup, or recover-root to rearm a spent attempt", flush=True)


def recover_root(private: Path) -> None:
    """Allow one more cold-boot attempt after a checked USB RAM recovery."""
    state = read_state(private)
    if not state.get("usb_serial") or not state.get("recovery_boot_id"):
        raise RuntimeError("Run python3 echo_plus2.py boot first")
    serial = wait_recovery(state["usb_serial"])
    boot_id = adb("shell", "cat /proc/sys/kernel/random/boot_id").strip()
    if serial != state["usb_serial"] or boot_id != state["recovery_boot_id"]:
        raise RuntimeError("USB recovery differs from the saved Echo or boot session")
    partitions = adb("shell", "cat /proc/partitions")
    if not any(re.fullmatch(r"\s*179\s+16\s+4987375\s+mmcblk0p16\s*", line)
               for line in partitions.splitlines()):
        raise RuntimeError("The checked Echo userdata partition is absent")
    if any(line.split()[1] == "/data" for line in adb("shell", "cat /proc/mounts").splitlines()):
        raise RuntimeError("/data is already mounted; inspect this recovery before continuing")
    if adb("shell", "if [ -e /dev/mmcblk0p16 ]; then echo present; else echo absent; fi").strip() != "absent":
        raise RuntimeError("The temporary userdata device node already exists")

    adb("shell", "mknod /dev/mmcblk0p16 b 179 16")
    adb("shell", "mount -t ext4 -o rw /dev/mmcblk0p16 /data")
    budget = "/data/data/org.local.lidar.binderprobe/files/autoroot_budget_v146"
    outcome = ""
    try:
        mounts = adb("shell", "cat /proc/mounts")
        if not any(line.startswith("/dev/mmcblk0p16 /data ext4 rw,")
                   for line in mounts.splitlines()):
            raise RuntimeError("The checked userdata partition is not mounted read-write")
        adb("shell", f"test -f {budget} && test ! -L {budget}")
        before = adb("exec-out", "cat", budget)
        if before not in {str(value) for value in range(11)}:
            raise RuntimeError("Root attempt budget is missing or has unexpected contents")
        backup = private / ("autoroot-budget-before-"
                            + time.strftime("%Y%m%d-%H%M%S-")
                            + secrets.token_hex(4) + ".bin")
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(before.encode("ascii"))
            output.flush()
            os.fsync(output.fileno())
        print(f"Saved the original root-attempt budget privately: {backup}", flush=True)
        if before == "0":
            command = (f"set -eu; p={budget}; "
                       '[ "$(cat "$p")" = 0 ]; '
                       '[ "$(wc -c < "$p")" -eq 1 ]; '
                       'printf 1 > "$p"; sync; '
                       '[ "$(cat "$p")" = 1 ]; '
                       '[ "$(wc -c < "$p")" -eq 1 ]')
            adb("shell", command)
            if adb("exec-out", "cat", budget) != "1":
                raise RuntimeError("The one-attempt budget did not read back as 1")
            outcome = "ROOT_ATTEMPT_REARMED"
        else:
            outcome = "ROOT_ATTEMPT_ALREADY_ARMED"
    finally:
        adb("shell", "sync; umount /data")
    if any(line.split()[1] == "/data" for line in adb("shell", "cat /proc/mounts").splitlines()):
        raise RuntimeError("/data did not unmount cleanly")
    print(outcome + ": power-cycle normally with Action released, then check the new boot", flush=True)


def persist(private: Path, tools: dict[str, object], *, resume_stock: bool = False) -> None:
    state = read_state(private)
    profile, slot = selected_firmware(state)
    if not state.get("usb_serial") or not state.get("recovery_boot_id"):
        raise RuntimeError("Run python3 echo_plus2.py boot first")
    # Reuse the recovery started by `boot`. A new BootROM cycle would make a
    # stale install state easy to mistake for the same running device.
    phase("Checking the selected Echo and boot session")
    serial = usb_serial_from_cmdline() if resume_stock else wait_recovery(state["usb_serial"])
    if serial != state["usb_serial"] or adb("shell", "cat /proc/sys/kernel/random/boot_id").strip() != state["recovery_boot_id"]:
        raise RuntimeError("Temporary recovery has restarted; run boot again")
    sdk = Path(tools["sdk"])
    env = os.environ.copy()
    env["ANDROID_SDK_ROOT"] = str(sdk)
    env["ECHO_HELPER_OUT"] = str(HELPER_BUILD)
    env["ECHO_APP_OUT"] = str(APP_BUILD)
    phase("Building the root helper and Android app")
    call("bash", ROOT / "src/persistence/helper/build.sh", env=env)
    call("bash", ROOT / "src/persistence/app/build.sh", env=env)
    key = private / "apk-signing.jks"
    password_file = private / "apk-signing-password.txt"
    if key.exists() and not password_file.is_file():
        raise RuntimeError("Signing key exists without its private password file")
    if not password_file.exists():
        fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(secrets.token_urlsafe(30) + "\n")
            output.flush()
            os.fsync(output.fileno())
    password = password_file.read_text().strip()
    if len(password) < 32:
        raise RuntimeError("Signing password file has unexpected contents")
    key_env = env.copy()
    key_env["ECHO_APK_SIGNING_PASSWORD"] = password
    if not key.exists():
        print("Creating a private APK signing key. Back up the key and its password for app updates.", flush=True)
        call("keytool", "-genkeypair", "-keystore", key, "-alias", "echo-plus2",
             "-keyalg", "RSA", "-keysize", "3072", "-validity", "3650",
             "-dname", "CN=Echo Plus 2 Root", "-storepass:env", "ECHO_APK_SIGNING_PASSWORD",
             "-keypass:env", "ECHO_APK_SIGNING_PASSWORD", "-noprompt", env=key_env)
    apk = APP_BUILD / "binderprobe.apk"
    call(sdk / "build-tools/36.0.0/apksigner", "sign", "--ks", key,
         "--ks-key-alias", "echo-plus2", "--ks-pass", f"file:{password_file}",
         "--v1-signing-enabled", "true",
         "--v2-signing-enabled", "false", "--out", apk,
         APP_BUILD / "binderprobe-unsigned.apk", env=key_env)
    call(sdk / "build-tools/36.0.0/apksigner", "verify", "--min-sdk-version", "23", apk)
    stock = private / "stock-init"
    stock.mkdir(mode=0o700, exist_ok=True)
    if resume_stock:
        for name in ("sepolicy", "init.mt8167.usb.rc", "init.usb.rc"):
            if not (stock / name).is_file():
                raise RuntimeError(f"Missing saved stock input for resume: {name}")
    else:
        for remote, name in (("/system_root/sepolicy", "sepolicy"),
                             ("/system_root/init.mt8167.usb.rc", "init.mt8167.usb.rc"),
                             ("/system_root/init.usb.rc", "init.usb.rc")):
            save_recovery_file(remote, stock / name)
    key_public = Path.home() / ".android/adbkey.pub"
    if not key_public.is_file():
        raise RuntimeError("Missing this host's existing ADB public key")
    public_copy = private / "adbkey.pub"
    if public_copy.exists() and public_copy.read_bytes() != key_public.read_bytes():
        raise RuntimeError("Saved ADB public key differs from this host")
    public_copy.write_bytes(key_public.read_bytes())
    call(tools["python"], ROOT / "src/bootstrap/stock-transition/build.py",
         "--policy", stock / "sepolicy", "--stock-usb-rc", stock / "init.mt8167.usb.rc",
         "--generic-usb-rc", stock / "init.usb.rc", "--clang", tools["clang"],
         "--ld", tools["ld"], "--policy-cc", tools["ndk_cc"], "--out", STOCK_BUILD,
         "--profile", profile.name)
    base = [tools["python"], ROOT / "src/bootstrap/stock-transition/install.py",
            "--policy", stock / "sepolicy", "--stock-usb-rc", stock / "init.mt8167.usb.rc",
            "--generic-usb-rc", stock / "init.usb.rc", "--apk", apk,
            "--built-dir", STOCK_BUILD, "--helper", HELPER_BUILD / "core_helper64",
            "--helper-sha256", sha(HELPER_BUILD / "core_helper64"),
            "--apk-sha256", sha(apk), "--adb-pubkey", public_copy,
            "--aapt", sdk / "build-tools/36.0.0/aapt",
            "--apksigner", sdk / "build-tools/36.0.0/apksigner",
            "--target-serial", serial, "--profile", profile.name,
            "--slot", slot]
    call(*base)
    phase("Installing and arming cold-boot root")
    call(*base, "--resume-stock" if resume_stock else "--run")
    state["installed_apk_sha256"] = sha(apk)
    state["install_boot_id"] = adb("shell", "cat /proc/sys/kernel/random/boot_id").strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", state["install_boot_id"]):
        raise RuntimeError("Could not record the installation boot ID")
    save_state(private, state)
    print("INSTALL_READY_FOR_COLD_BOOT. Release Action and power-cycle normally.", flush=True)
    print("Then run: python3 echo_plus2.py verify", flush=True)


def verify(private: Path) -> None:
    use_sdk_platform_tools(detect_sdk())
    state = read_state(private)
    profile, slot = selected_firmware(state)
    if not all(state.get(key) for key in ("installed_apk_sha256", "usb_serial", "install_boot_id")):
        raise RuntimeError("No completed install is recorded in the private setup state")
    print("Waiting up to 360 seconds for the normally booted Echo over USB ADB...", flush=True)
    wait_start = time.monotonic()
    deadline = wait_start + 360
    next_report = wait_start + 30
    while True:
        try:
            connection = subprocess.run(["adb", "-d", "get-state"],
                                        capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            connection = None
        if (connection is not None and connection.returncode == 0
                and connection.stdout.strip() == "device"):
            break
        now = time.monotonic()
        if now >= deadline:
            raise RuntimeError("USB ADB did not appear within 360 seconds. "
                               "Cold-boot root is not verified; do not rerun persist or configure blindly")
        if now >= next_report:
            print(f"Still waiting for USB ADB ({int(now - wait_start)} seconds elapsed)...",
                  flush=True)
            next_report = now + 30
        time.sleep(2)
    # Recovery adbd was root and could read /proc/cmdline. Stock adbd is the
    # ordinary shell user, so SELinux correctly denies that file. Match the
    # USB transport serial against Android's read-only serial property here.
    deadline = time.monotonic() + 60
    while True:
        try:
            transport = adb("get-state").strip()
            serial = adb("get-serialno").strip()
            property_serial = adb("shell", "getprop ro.serialno").strip()
            hardware = adb("shell", "getprop ro.boot.hardware").strip()
        except subprocess.CalledProcessError:
            transport = serial = property_serial = hardware = ""
        if transport == "device" and serial and property_serial and hardware:
            if (serial != state["usb_serial"] or property_serial != serial
                    or hardware != "mt8167"):
                raise RuntimeError("Connected stock USB device is not the installed Echo")
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Stock USB ADB identity did not become ready within 60 seconds")
        time.sleep(2)
    if adb("shell", "cat /proc/sys/kernel/random/boot_id").strip() == state["install_boot_id"]:
        raise RuntimeError("The Echo has not restarted since installation")
    if adb("shell", "getprop ro.build.fingerprint").strip() != profile.fingerprint:
        raise RuntimeError("Stock firmware differs from the supported build")
    if adb("shell", "getprop ro.boot.slot_suffix").strip() != "_" + slot:
        raise RuntimeError("Stock Android is not running the selected boot slot")
    # USB ADB can appear before Android finishes starting. A check launched as
    # soon as the cable reconnects should wait for the completed stock boot.
    deadline = time.monotonic() + 180
    while True:
        try:
            boot = subprocess.run(["adb", "-d", "shell", "getprop", "sys.boot_completed"],
                                  capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            boot = None
        if boot is not None and boot.returncode == 0 and boot.stdout.strip() == "1":
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Stock Android did not complete booting within 180 seconds")
        time.sleep(2)
    # Query the live, current-boot helper. A log line alone could be stale,
    # and logcat buffers may not retain the app's earlier report.
    client = HELPER_BUILD / "usb_root_client"
    if not client.is_file():
        raise RuntimeError("Build the USB root client before verification")
    remote_client = "/data/local/tmp/lidar-root-client"
    adb("push", str(client), remote_client)
    adb("shell", "chmod", "0755", remote_client)
    # The app's BootCompleted receiver may still be finishing its exploit
    # when Android first reports boot complete. Wait for the live broker,
    # without treating an earlier connection failure as a failed cold boot.
    identity_command = f"{shlex.quote(remote_client)} {shlex.quote('id')}"
    deadline = time.monotonic() + 90
    while True:
        try:
            reply = subprocess.run(["adb", "-d", "shell", identity_command],
                                   capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            reply = None
        if reply is not None and reply.returncode == 0:
            identity = reply.stdout
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("The current-boot root helper did not answer within 90 seconds")
        time.sleep(2)
    capabilities = adb("shell", f"{shlex.quote(remote_client)} {shlex.quote('cat /proc/self/status')}")
    if ("uid=0(root)" not in identity or "BRIDGE_EXIT=0" not in identity or
            f"CapEff:\t{FULL_CAPS}" not in capabilities or
            f"CapBnd:\t{FULL_CAPS}" not in capabilities or
            "BRIDGE_EXIT=0" not in capabilities):
        raise RuntimeError("The current-boot root helper lacks UID 0 or full capabilities")
    print(f"COLD_BOOT_ROOT_OBSERVED on {profile.name} slot {slot.upper()}", flush=True)


def verify_usb_identity(private: Path) -> None:
    """Check the selected stock Echo without needing the short-lived root broker."""
    state = read_state(private)
    profile, slot = selected_firmware(state)
    serial = state.get("usb_serial")
    if not serial:
        raise RuntimeError("No installed Echo is recorded in local/device")
    if (adb("get-state").strip() != "device" or
            adb("get-serialno").strip() != serial or
            adb("shell", "getprop", "ro.serialno").strip() != serial or
            adb("shell", "getprop", "ro.boot.hardware").strip() != "mt8167" or
            adb("shell", "getprop", "ro.build.fingerprint").strip() != profile.fingerprint or
            adb("shell", "getprop", "ro.boot.slot_suffix").strip() != "_" + slot):
        raise RuntimeError("USB ADB does not identify as the installed Echo Plus 2")


def main() -> None:
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtkclient-root", type=Path, default=MTK_ROOT)
    parser.add_argument("--private-dir", type=Path, default=DEVICE)
    commands = parser.add_subparsers(dest="stage", required=True)
    commands.add_parser("check", help="check local dependencies without device access")
    dump_parser = commands.add_parser("dump", help="read and check this Echo's firmware, then build its RAM image")
    dump_parser.add_argument("--reuse", action="store_true", help="verify prior capture and rebuild offline")
    commands.add_parser("diagnose", help="read another firmware for offset analysis without building a RAM image")
    boot_parser = commands.add_parser("boot", help="boot temporary root from RAM")
    boot_parser.add_argument("--resume", action="store_true",
                             help="adopt the current USB recovery after an interrupted boot command")
    commands.add_parser("recover-root", help="back up and rearm one cold-boot root attempt from USB RAM recovery")
    persist_parser = commands.add_parser("persist", help="install cold-boot root from the running temporary recovery")
    persist_parser.add_argument("--resume-stock", action="store_true",
                                help="finish installation after a checked stock-init handoff")
    commands.add_parser("verify", help="check root evidence after an ordinary cold boot")
    gate_parser = commands.add_parser("configure", help="optionally install Kiosk Satellite and the early WiFi gate")
    gate_parser.add_argument("--config", type=Path, default=LOCAL / "config.toml")
    gate_parser.add_argument("--check", action="store_true", help="check the private config and APK without device access")
    status_parser = commands.add_parser("gate-status", help="check the current boot's WiFi gate and optional network ADB")
    status_parser.add_argument("--config", type=Path, default=LOCAL / "config.toml")
    commands.add_parser("kiosk-setup", help="start installed Kiosk Satellite and forward its setup page over USB")
    args = parser.parse_args()
    if args.stage == "check":
        host(args, android=True)
        print("HOST_PREFLIGHT_OK", flush=True)
        return
    if args.stage == "configure" and args.check:
        setup = configure_gate.load(args.config)
        if setup.kiosk_apk is not None:
            sdk = detect_sdk()
            configure_gate.check_apk(setup.kiosk_apk, sdk / "build-tools/36.0.0/aapt")
        print("GATE_CONFIG_OK: no device access", flush=True)
        print("On apply: WiFi gate; "
              f"Kiosk Satellite {'installed' if setup.install_kiosk else 'skipped'}; "
              f"authenticated WiFi ADB {'on' if setup.network_adb else 'off'}; "
              f"Amazon lockdown {'on' if setup.amazon_lockdown else 'off'}", flush=True)
        return
    private = private_dir(args.private_dir)
    if args.stage == "verify":
        verify(private)
        return
    if args.stage == "kiosk-setup":
        use_sdk_platform_tools(detect_sdk())
        verify_usb_identity(private)
        configure_gate.start_kiosk()
        return
    if args.stage == "recover-root":
        use_sdk_platform_tools(detect_sdk())
        recover_root(private)
        return
    if args.stage in {"configure", "gate-status"}:
        if selected_firmware(read_state(private)) != (NS6575_8338N, "a"):
            raise RuntimeError("The optional WiFi gate is device-tested only on NS6575/8338N slot A")
        sdk = detect_sdk()
        use_sdk_platform_tools(sdk)
        if args.stage == "configure":
            configure_gate.configure(private, args.config,
                                    sdk / "build-tools/36.0.0/aapt",
                                    verify, verify_usb_identity)
        else:
            setup = configure_gate.load(args.config)
            verify(private)
            configure_gate.verify_gate(setup.network_adb, setup.install_kiosk)
            if setup.amazon_lockdown:
                configure_gate.verify_amazon_lockdown()
        return
    tools = host(args, android=args.stage == "persist")
    print("HOST_PREFLIGHT_OK", flush=True)
    if args.stage == "dump":
        dump(args, private, tools)
    elif args.stage == "diagnose":
        diagnose_firmware(private, tools)
    elif args.stage == "boot":
        boot(private, tools, resume=args.resume)
    elif args.stage == "persist":
        persist(private, tools, resume_stock=args.resume_stock)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as error:
        print(f"ROOT_SETUP_STOPPED: {error}", file=sys.stderr)
        raise SystemExit(1)
