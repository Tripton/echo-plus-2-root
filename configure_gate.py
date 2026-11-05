"""Install the optional WiFi gate after the checked cold-boot root proof.

The host reads one private TOML file, stages a WiFi profile while the Echo has
no network address, and arms the already installed app for the next boot. No
credential, device serial, or authorized key is printed or committed.
"""

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import tomllib
from urllib.parse import quote
import xml.etree.ElementTree as ET


PACKAGE = "org.local.lidar.binderprobe"
KIOSK = "me.jxl.kiosk_satellite"
CLIENT = "/data/local/tmp/lidar-root-client"
REMOTE = "/data/local/tmp/echo-plus2-gate-setup"
POLICY = f"/data/user_de/0/{PACKAGE}/files/early_gate_policy_v151"
READY = f"/data/user_de/0/{PACKAGE}/files/early_gate_ready_v151"
WORKER_BUILD = Path(__file__).resolve().parent / "local/build/helper"


@dataclass(frozen=True)
class Setup:
    ssid: str
    password: str
    kiosk_apk: Path | None
    network_adb: bool
    install_kiosk: bool
    amazon_lockdown: bool

STAGE = """#!/system/bin/sh
set -eu
app_uid=$1
network=$2
lockdown=$3
workers=$4
case "$app_uid" in ''|*[!0-9]*) exit 2;; esac
case "$network" in 0|1) ;; *) exit 2;; esac
case "$lockdown" in 0|1) ;; *) exit 2;; esac
case "$workers" in 0|1) ;; *) exit 2;; esac
active=/data/misc/wifi/wpa_supplicant.conf
backup=/data/local/tmp/echo-plus2-gate-previous-wifi.conf
profile=/data/local/tmp/echo-plus2-gate-setup/profile.conf
policy=/data/user_de/0/org.local.lidar.binderprobe/files/early_gate_policy_v151
net=/data/lidar-network-adb.conf
amazon=/data/lidar-amazon-lockdown.conf
mic=/data/lidar-kiosk-mic-keeper
buttons=/data/lidar-kiosk-buttons
test -f "$active" && test -f "$profile"
test ! -e "$backup" && test ! -e "$policy" && test ! -e "$net" && test ! -e "$amazon"
if [ "$workers" = 1 ]; then
    test -f /data/local/tmp/echo-plus2-gate-setup/mic
    test -f /data/local/tmp/echo-plus2-gate-setup/buttons
    test ! -e "$mic" && test ! -e "$buttons"
fi
cp "$active" "$backup"
chown 2000:2000 "$backup"
chmod 0600 "$backup"
cp "$profile" "$active.echo-plus2-new"
chown 1010:1010 "$active.echo-plus2-new"
chmod 0660 "$active.echo-plus2-new"
mv "$active.echo-plus2-new" "$active"
restorecon "$active"
printf 'mode=continuous\\n' > "$policy.tmp"
chown "$app_uid:$app_uid" "$policy.tmp"
chmod 0600 "$policy.tmp"
restorecon "$policy.tmp"
mv "$policy.tmp" "$policy"
if [ "$network" = 1 ]; then
    cp /data/local/tmp/echo-plus2-gate-setup/network-adb.conf "$net"
    chown 0:0 "$net"
    chmod 0600 "$net"
    restorecon "$net"
fi
if [ "$lockdown" = 1 ]; then
    printf 'enabled=1\\n' > "$amazon.tmp"
    chown 0:0 "$amazon.tmp"
    chmod 0600 "$amazon.tmp"
    restorecon "$amazon.tmp"
    mv "$amazon.tmp" "$amazon"
fi
if [ "$workers" = 1 ]; then
    cp /data/local/tmp/echo-plus2-gate-setup/mic "$mic.tmp"
    chown 0:0 "$mic.tmp"
    chmod 0500 "$mic.tmp"
    chcon u:object_r:shell_data_file:s0 "$mic.tmp"
    /system/bin/cmp -s "$mic.tmp" /data/local/tmp/echo-plus2-gate-setup/mic
    mv "$mic.tmp" "$mic"
    cp /data/local/tmp/echo-plus2-gate-setup/buttons "$buttons.tmp"
    chown 0:0 "$buttons.tmp"
    chmod 0500 "$buttons.tmp"
    chcon u:object_r:shell_data_file:s0 "$buttons.tmp"
    /system/bin/cmp -s "$buttons.tmp" /data/local/tmp/echo-plus2-gate-setup/buttons
    mv "$buttons.tmp" "$buttons"
fi
sync
echo CONFIG_STAGE_OK
"""


def run(*args: str, timeout: int = 30) -> str:
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        tool = Path(args[0]).name
        operation = ""
        if tool == "adb" and len(args) > 1:
            command_at = 2 if args[1] == "-d" else 3 if args[1] == "-s" else 1
            if len(args) > command_at:
                operation = args[command_at]
                if (operation == "shell" and len(args) > command_at + 1 and
                        re.fullmatch(r"[A-Za-z0-9_./-]+", args[command_at + 1])):
                    operation += " " + Path(args[command_at + 1]).name
        elif len(args) > 1:
            operation = args[1]
        raise RuntimeError(f"{tool} {operation} failed (exit {result.returncode})".strip())
    return result.stdout.strip()


def adb(*args: str, timeout: int = 30) -> str:
    return run("adb", "-d", *args, timeout=timeout)


def adb_read(*args: str, timeout: int = 30, retry_seconds: int = 45) -> str:
    """Retry an observation while USB adbd settles after Android starts."""
    deadline = time.monotonic() + retry_seconds
    while True:
        try:
            return adb(*args, timeout=timeout)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            if time.monotonic() >= deadline:
                operation = args[0] if args else "unknown"
                raise RuntimeError(
                    f"USB ADB read {operation} remained unavailable after "
                    f"{retry_seconds} seconds: {error}") from None
            time.sleep(2)


def root(command: str) -> str:
    try:
        result = adb("shell", f'{CLIENT} "{command}"', timeout=30)
    except RuntimeError as error:
        if "failed (exit 4)" in str(error):
            raise RuntimeError("The local root broker socket is unavailable; "
                               "its 15-minute or 16-command limit may be exhausted") from None
        raise
    if "BRIDGE_EXIT=0" not in result:
        raise RuntimeError("The current-boot USB root broker did not complete the command")
    return result


def root_read(command: str) -> str:
    """Read through the current-boot root broker without replaying a mutation."""
    result = adb_read("shell", f'{CLIENT} "{command}"')
    if "BRIDGE_EXIT=0" not in result:
        raise RuntimeError("The current-boot USB root broker did not complete its read")
    return result


def load(path: Path) -> Setup:
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError("Keep the selected configuration private with mode 0600")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if not {"wifi", "kiosk", "adb"} <= set(data) or set(data) - {"wifi", "kiosk", "adb", "amazon"}:
        raise RuntimeError("The config tables differ from config.example.toml")
    wifi, kiosk, adb_config = data["wifi"], data["kiosk"], data["adb"]
    if not all(isinstance(section, dict) for section in (wifi, kiosk, adb_config)):
        raise RuntimeError("wifi, kiosk, and adb must be tables")
    if (set(wifi) != {"ssid", "password"} or
            set(kiosk) != {"install", "apk"} or
            set(adb_config) != {"network"}):
        raise RuntimeError("The config fields differ from config.example.toml")
    ssid, password = wifi["ssid"], wifi["password"]
    if (not isinstance(ssid, str) or not 1 <= len(ssid.encode("utf-8")) <= 32 or
            any(ord(character) < 32 for character in ssid)):
        raise RuntimeError("WiFi SSID must contain 1–32 UTF-8 bytes without controls")
    if not isinstance(password, str) or not 8 <= len(password) <= 63:
        raise RuntimeError("WiFi password must contain 8–63 characters")
    if not isinstance(kiosk["install"], bool):
        raise RuntimeError("kiosk.install must be true or false")
    if not isinstance(kiosk["apk"], str):
        raise RuntimeError("kiosk.apk must be an absolute file path")
    apk = Path(kiosk["apk"]).expanduser()
    if kiosk["install"] and (not apk.is_absolute() or not apk.is_file()):
        raise RuntimeError("Set kiosk.apk to the downloaded APK's absolute path")
    if not isinstance(adb_config["network"], bool):
        raise RuntimeError("adb.network must be true or false")
    amazon = data.get("amazon", {"lockdown": True})
    if not isinstance(amazon, dict) or set(amazon) != {"lockdown"} or not isinstance(amazon["lockdown"], bool):
        raise RuntimeError("amazon.lockdown must be true or false")
    selected_apk = apk if kiosk["install"] else None
    return Setup(ssid, password, selected_apk, adb_config["network"],
                 kiosk["install"], amazon["lockdown"])


def check_apk(apk: Path, aapt: Path) -> None:
    badging = run(str(aapt), "dump", "badging", str(apk), timeout=30)
    if not re.search(r"^package: name='me\.jxl\.kiosk_satellite' ", badging, re.M):
        raise RuntimeError("kiosk.apk is not Kiosk Satellite")


def check_workers() -> dict[str, Path]:
    """Check the locally built optional workers without touching the Echo."""
    manifest = json.loads((WORKER_BUILD / "workers.json").read_text())
    if set(manifest) != {"mic", "buttons"}:
        raise RuntimeError("The built Kiosk worker manifest differs")
    workers = {"mic": WORKER_BUILD / "kiosk_mic_keeper",
               "buttons": WORKER_BUILD / "key_forwarder"}
    for name, path in workers.items():
        expected = manifest[name]
        if (not isinstance(expected, dict) or set(expected) != {"sha256", "bytes"} or
                not isinstance(expected["bytes"], int) or expected["bytes"] < 1000 or
                not re.fullmatch(r"[0-9a-f]{64}", str(expected["sha256"])) or
                path.stat().st_size != expected["bytes"]):
            raise RuntimeError(f"Built {name} worker has unexpected metadata")
        with path.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != expected["sha256"]:
                raise RuntimeError(f"Built {name} worker differs from its manifest")
    helper = (WORKER_BUILD / "core_helper64").read_bytes()
    for name in workers:
        if manifest[name]["sha256"].encode("ascii") not in helper:
            raise RuntimeError(f"Root helper does not pin the built {name} worker")
    return workers


def stage(local: Path, remote: str) -> None:
    adb("push", str(local), remote, timeout=90)
    adb("shell", "chmod", "0600", remote)
    with tempfile.TemporaryDirectory(prefix="echo-plus2-stage-") as directory:
        copy = Path(directory) / "readback"
        adb("pull", remote, str(copy), timeout=90)
        if hashlib.sha256(local.read_bytes()).digest() != hashlib.sha256(copy.read_bytes()).digest():
            raise RuntimeError("Staged file readback differs")


def private_file(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def archive_previous_gate_inputs(private: Path) -> None:
    """Keep an earlier host backup when a factory reset starts a new setup."""
    names = ("wifi-before-gate.conf", "adb-keys-readback",
             "wifi-gate-profile.conf", "network-adb.conf", "gate-setup.sh")
    existing = [private / name for name in names
                if (private / name).exists() or (private / name).is_symlink()]
    if not existing:
        return
    for source in existing:
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"Unexpected private gate input: {source.name}")
    history = private / "gate-history"
    if history.is_symlink():
        raise RuntimeError("Private gate history must not be a symlink")
    history.mkdir(mode=0o700, exist_ok=True)
    if history.stat().st_mode & 0o077:
        raise RuntimeError("Private gate history must have mode 0700")
    archive = history / str(time.time_ns())
    archive.mkdir(mode=0o700)
    for source in existing:
        source.rename(archive / source.name)
    print("Previous private gate inputs preserved under local/device/gate-history", flush=True)


def backup_stock(private: Path) -> tuple[bytes, bytes]:
    wifi_path = private / "wifi-before-gate.conf"
    key_path = private / "adb-keys-readback"
    if wifi_path.exists() or key_path.exists():
        raise RuntimeError("Existing private gate backup: inspect before retrying")
    root("/system/bin/sh -c 'test ! -e /data/local/tmp/echo-plus2-gate-setup-before-wifi.conf && "
         "cp /data/misc/wifi/wpa_supplicant.conf /data/local/tmp/echo-plus2-gate-setup-before-wifi.conf && "
         "cp /data/misc/adb/adb_keys /data/local/tmp/echo-plus2-gate-setup-adb-keys && "
         "chown 2000:2000 /data/local/tmp/echo-plus2-gate-setup-before-wifi.conf "
         "/data/local/tmp/echo-plus2-gate-setup-adb-keys && "
         "chmod 0600 /data/local/tmp/echo-plus2-gate-setup-before-wifi.conf "
         "/data/local/tmp/echo-plus2-gate-setup-adb-keys'")
    adb("pull", "/data/local/tmp/echo-plus2-gate-setup-before-wifi.conf", str(wifi_path))
    adb("pull", "/data/local/tmp/echo-plus2-gate-setup-adb-keys", str(key_path))
    os.chmod(wifi_path, 0o600)
    os.chmod(key_path, 0o600)
    if key_path.read_bytes() != (private / "adbkey.pub").read_bytes():
        raise RuntimeError("Installed ADB key differs from this guide's saved public key")
    return wifi_path.read_bytes(), key_path.read_bytes()


def profile(stock: bytes, ssid: str, password: str) -> bytes:
    try:
        header = stock.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeError("The stock WiFi profile is not UTF-8") from None
    if "network={" in header or "ctrl_interface=" not in header or not header.endswith("\n"):
        raise RuntimeError("This guide only imports WiFi into a clean, unconfigured profile")
    key = hashlib.pbkdf2_hmac("sha1", password.encode(), ssid.encode(), 4096, 32).hex()
    identity = quote(json.dumps({"configKey": f'"{ssid}"WPA_PSK', "creatorUid": "-1"},
                                separators=(",", ":")), safe="")
    return (header + "network={\n" + "\tssid=" + json.dumps(ssid, ensure_ascii=False) +
            "\n\tpsk=" + key + "\n\tkey_mgmt=WPA-PSK WPA-PSK-SHA256\n" +
            '\tid_str="' + identity + '"\n}\n').encode("utf-8")


def package_uid(name: str, *, postboot: bool = False) -> int:
    read = adb_read if postboot else adb
    details = read("shell", "dumpsys", "package", name, timeout=30)
    found = re.search(r"\buserId=(\d+)\b", details)
    if not found or not 10000 <= int(found.group(1)) <= 19999:
        raise RuntimeError(f"Package UID is missing or invalid: {name}")
    return int(found.group(1))


def wifi_has_ip() -> bool:
    ipv4 = adb("shell", "ip", "-4", "addr", "show", "wlan0")
    ipv6 = adb("shell", "ip", "-6", "addr", "show", "wlan0")
    return bool(re.search(r"\binet\s", ipv4) or
                re.search(r"\binet6\s+[^\n]+\bscope global\b", ipv6))


def verify_saved_preboot(amazon_lockdown: bool) -> None:
    """Prove the next boot's inputs are on disk before leaving USB root."""
    adb("shell", "sync", timeout=30)
    command = ("cat /data/data/org.local.lidar.binderprobe/files/autoroot_budget_v146; "
               "echo GATE_SETTINGS; cat /data/system/users/0/settings_global.xml; "
               "echo GATE_PACKAGES; cat /data/system/users/0/package-restrictions.xml; "
               "echo GATE_END")
    for attempt in range(3):
        time.sleep(3)
        report = root(command)
        try:
            budget, rest = report.split("GATE_SETTINGS\n", 1)
            settings_text, rest = rest.split("GATE_PACKAGES\n", 1)
            packages_text, rest = rest.split("GATE_END\n", 1)
            settings = ET.fromstring(settings_text.strip())
            packages = ET.fromstring(packages_text.strip())
            saved_wifi = next((entry.get("value") for entry in settings.iter()
                               if entry.get("name") == "wifi_on"), None)
            saved_packages = {entry.get("name"): entry.attrib
                              for entry in packages.iter() if entry.get("name")}
            ready = (budget.strip() == "1" and saved_wifi == "0" and
                     saved_packages.get(PACKAGE, {}).get("stopped") != "true")
            if amazon_lockdown:
                ready = (ready and
                         saved_packages.get("amazon.speech.sim", {}).get("inst") == "false" and
                         all(saved_packages.get(name, {}).get("enabled") == "3"
                             for name in ("com.amazon.device.software.ota",
                                          "com.amazon.echo.csm.oobe")))
        except (ValueError, ET.ParseError):
            ready = False
        if ready and adb("shell", "settings", "get", "global", "wifi_on") == "0" and not wifi_has_ip():
            print("PERSISTED_PREBOOT_CHECK_OK", flush=True)
            return
    raise RuntimeError("Boot budget, WiFi preference, or package changes were not saved; "
                       "stopped before reboot")


def check_unconfigured_gate() -> None:
    """Require a clean, offline device before staging any gate files."""
    if adb("shell", "settings", "get", "global", "wifi_on") not in {"0", "1"}:
        raise RuntimeError("Unexpected WiFi preference")
    if wifi_has_ip():
        raise RuntimeError("WiFi already has an IP; start from an offline Echo")
    root("/system/bin/sh -c 'test ! -e /data/user_de/0/org.local.lidar.binderprobe/files/early_gate_policy_v151 && "
         "test ! -e /data/local/tmp/echo-plus2-gate-previous-wifi.conf && "
         "test ! -e /data/lidar-network-adb.conf && "
         "test ! -e /data/lidar-amazon-lockdown.conf'")


def configure(private: Path, config_path: Path, aapt: Path,
              verify_root, verify_usb_identity) -> None:
    setup = load(config_path)
    if setup.kiosk_apk is not None:
        check_apk(setup.kiosk_apk, aapt)
    workers = check_workers()
    print("Checking the selected Echo over USB", flush=True)
    verify_usb_identity(private)
    if adb("shell", "getprop", "sys.boot_completed") != "1":
        raise RuntimeError("Stock Android has not finished starting")
    if wifi_has_ip():
        raise RuntimeError("WiFi already has an IP; start from an offline Echo")
    # The local root broker has a 16-command budget per boot. Verification or
    # earlier diagnostics may have used most of it before configure starts.
    # Renew it after USB identity checks but before changing any on-device
    # state, even if the previous boot's broker has already expired.
    print("Refreshing the bounded root session before configuration", flush=True)
    adb("reboot")
    verify_root(private)
    check_unconfigured_gate()
    adb("shell", "mkdir", "-p", REMOTE)
    expected_helper = REMOTE + "/expected-helper"
    stage(WORKER_BUILD / "core_helper64", expected_helper)
    root(f"/system/bin/cmp -s /data/x {expected_helper}")
    adb("shell", "rm", "-f", expected_helper)
    if not setup.install_kiosk and adb("shell", "pm", "path", KIOSK):
        raise RuntimeError("Kiosk is already installed; use a clean device for kiosk.install=false")
    # Back up and validate the stock files before installing an app or changing
    # a network preference. The clean-device checks above guard both boots.
    archive_previous_gate_inputs(private)
    print("Saving and checking the private stock WiFi and ADB-key backup", flush=True)
    stock, keys = backup_stock(private)
    profile_path = private / "wifi-gate-profile.conf"
    private_file(profile_path, profile(stock, setup.ssid, setup.password))
    network_path = private / "network-adb.conf"
    if setup.network_adb:
        value = "enabled=1\nkey_sha256=" + hashlib.sha256(keys).hexdigest() + "\n"
        private_file(network_path, value.encode("ascii"))
    script = private / "gate-setup.sh"
    private_file(script, STAGE.encode("ascii"))
    print("Staging the offline WiFi profile", flush=True)
    if setup.install_kiosk:
        print("Installing Kiosk Satellite", flush=True)
        adb("install", "-r", str(setup.kiosk_apk), timeout=180)
    app_uid = package_uid(PACKAGE)
    if setup.install_kiosk:
        package_uid(KIOSK)
    adb("shell", "settings", "put", "global", "wifi_on", "0")
    # Some stock builds kill this short-lived shell after applying the setting.
    # The two readbacks below, rather than its exit code, decide whether setup
    # may continue.
    subprocess.run(["adb", "-d", "shell", "svc", "wifi", "disable"],
                   capture_output=True, text=True, timeout=30)
    if adb("shell", "settings", "get", "global", "wifi_on") != "0":
        raise RuntimeError("WiFi next-boot preference is not off")
    if wifi_has_ip():
        raise RuntimeError("WiFi still has an IP; setup stopped before staging")
    stage(profile_path, REMOTE + "/profile.conf")
    stage(script, REMOTE + "/stage.sh")
    if setup.network_adb:
        stage(network_path, REMOTE + "/network-adb.conf")
    if setup.install_kiosk:
        stage(workers["mic"], REMOTE + "/mic")
        stage(workers["buttons"], REMOTE + "/buttons")
    result = root(f"/system/bin/sh {REMOTE}/stage.sh {app_uid} "
                  f"{int(setup.network_adb)} {int(setup.amazon_lockdown)} "
                  f"{int(setup.install_kiosk)}")
    if "CONFIG_STAGE_OK" not in result:
        raise RuntimeError("Gate setup did not report a completed stage")
    if setup.amazon_lockdown:
        disable_amazon_voice()
        disable_amazon_package("com.amazon.device.software.ota")
        disable_amazon_package("com.amazon.echo.csm.oobe")
    adb("shell", "rm", "-f", REMOTE + "/profile.conf", REMOTE + "/network-adb.conf",
        REMOTE + "/mic", REMOTE + "/buttons")
    verify_saved_preboot(setup.amazon_lockdown)
    print("GATE_STAGE_READY: rebooting the Echo with WiFi initially off", flush=True)
    adb("reboot")
    print("Waiting for ordinary Android boot and current-boot filter checks", flush=True)
    verify_root(private)
    print("Checking the current-boot WiFi gate", flush=True)
    verify_gate(setup.network_adb, setup.install_kiosk)
    if setup.amazon_lockdown:
        print("Checking Amazon lockdown", flush=True)
        verify_amazon_lockdown()
    print("Clearing the stock startup LED pattern if present", flush=True)
    clear_stale_startup_led()
    if setup.install_kiosk:
        print("Opening Kiosk Satellite setup", flush=True)
        start_kiosk()
        verify_workers()


def disable_amazon_voice() -> None:
    package = "amazon.speech.sim"
    details = adb("shell", "dumpsys", "package", package)
    match = re.search(r"^\s*User 0:.*\binstalled=(true|false)\b", details, re.M)
    if not match:
        raise RuntimeError("Cannot establish Alexa voice package state for user 0")
    if match.group(1) == "false":
        print("AMAZON_VOICE_ALREADY_DISABLED", flush=True)
        return
    print("Disabling the stock Alexa voice package for user 0", flush=True)
    result = root("ANDROID_DATA=/data ANDROID_ROOT=/system "
                  "/system/bin/runcon u:r:shell:s0 /system/bin/sh /system/bin/pm "
                  "uninstall -k --user 0 amazon.speech.sim")
    if "Success\n" not in result:
        raise RuntimeError("Alexa voice package removal did not report Success")
    details = adb("shell", "dumpsys", "package", package)
    if not re.search(r"^\s*User 0:.*\binstalled=false\b", details, re.M):
        raise RuntimeError("Alexa voice package removal did not read back")
    print("AMAZON_VOICE_DISABLED_FOR_USER_0", flush=True)


def disable_amazon_package(package: str) -> None:
    if package not in {"com.amazon.device.software.ota", "com.amazon.echo.csm.oobe"}:
        raise ValueError("Unexpected Amazon package")
    details = adb("shell", "dumpsys", "package", package)
    match = re.search(r"^\s*User 0:.*\benabled=(\d+)\b", details, re.M)
    if not match:
        raise RuntimeError(f"Cannot establish package state for {package}")
    if match.group(1) == "3":
        return
    if match.group(1) != "0":
        raise RuntimeError(f"Unexpected starting package state for {package}")
    result = root("ANDROID_DATA=/data ANDROID_ROOT=/system "
                  "/system/bin/runcon u:r:shell:s0 /system/bin/sh /system/bin/pm "
                  f"disable-user --user 0 {package}")
    if "new state: disabled-user" not in result:
        raise RuntimeError(f"Disabling {package} did not report disabled-user")
    details = adb("shell", "dumpsys", "package", package)
    if not re.search(r"^\s*User 0:.*\benabled=3\b", details, re.M):
        raise RuntimeError(f"Disabling {package} did not read back")
    print(f"AMAZON_PACKAGE_DISABLED_FOR_USER_0: {package}", flush=True)


def verify_amazon_lockdown() -> None:
    details = adb_read("shell", "dumpsys", "package", "amazon.speech.sim")
    if not re.search(r"^\s*User 0:.*\binstalled=false\b", details, re.M):
        raise RuntimeError("Alexa voice package returned after reboot")
    process = adb_read("shell", "sh", "-c", "pidof amazon.speech.sim || true")
    if process:
        raise RuntimeError("Alexa voice process is still running after reboot")
    for package in ("com.amazon.device.software.ota", "com.amazon.echo.csm.oobe"):
        details = adb_read("shell", "dumpsys", "package", package)
        if not re.search(r"^\s*User 0:.*\benabled=3\b", details, re.M):
            raise RuntimeError(f"Amazon package enabled after reboot: {package}")
    status = root_read("/system/bin/sh -c 'cat /data/lidar-amazon-lockdown.conf; "
                  "cat /data/lidar-amazon-stop-v159.log'")
    if ("enabled=1\n" not in status or
            "update_engine_rc=0 ahe_rc=0 amazonfiled_rc=0" not in status):
        raise RuntimeError("Amazon service-stop policy did not complete")
    for service in ("update_engine", "ahe", "amazonfiled"):
        if adb_read("shell", "getprop", f"init.svc.{service}") != "stopped":
            raise RuntimeError(f"Amazon service is running: {service}")
    jobs = adb_read("shell", "dumpsys", "jobscheduler", timeout=45)
    if "com.amazon.device.software.ota/.OTAJobService" in jobs:
        raise RuntimeError("Amazon OTA jobs remain scheduled")
    print("AMAZON_LOCKDOWN_OBSERVED_AFTER_REBOOT", flush=True)


def clear_stale_startup_led() -> None:
    pattern = adb_read("shell", "/system/bin/ledctrl", "--get_active_patterns")
    if "getPattern: anim_start_phase2" not in pattern:
        return
    result = adb("shell", "/system/bin/ledctrl", "--unset_pattern=anim_start_phase2")
    if "clearPattern: anim_start_phase2" not in result:
        raise RuntimeError("The stale Amazon startup LED pattern was not cleared")
    pattern = adb_read("shell", "/system/bin/ledctrl", "--get_active_patterns")
    if "getPattern: anim_start_phase2" in pattern:
        raise RuntimeError("The stale Amazon startup LED pattern returned")
    print("STALE_STARTUP_LED_CLEARED", flush=True)


def start_kiosk() -> None:
    # A newly installed Android package is stopped until first launched, so
    # BOOT_COMPLETED alone cannot start Kiosk on its first post-install boot.
    adb("shell", "pm", "grant", KIOSK, "android.permission.RECORD_AUDIO")
    package = adb_read("shell", "dumpsys", "package", KIOSK)
    if "android.permission.RECORD_AUDIO: granted=true" not in package:
        raise RuntimeError("Kiosk microphone permission was not granted")
    adb("shell", "am", "start", "-n", KIOSK + "/.MainActivity")
    deadline = time.monotonic() + 60
    while True:
        listeners = adb_read("shell", "netstat", "-ltn")
        if re.search(r"(?:0\.0\.0\.0|::):2324\s", listeners):
            local_port = adb("forward", "tcp:0", "tcp:2324")
            if not local_port.isdigit() or not 1 <= int(local_port) <= 65535:
                raise RuntimeError("USB forwarding did not provide a local Kiosk port")
            print(f"KIOSK_SETUP_READY: http://127.0.0.1:{local_port}", flush=True)
            return
        if time.monotonic() > deadline:
            raise RuntimeError("Kiosk did not open its setup port; the WiFi gate is already active")
        time.sleep(2)


def verify_workers() -> None:
    deadline = time.monotonic() + 30
    while True:
        report = root_read("/system/bin/sh -c 'cat /data/lidar-root-v154.marker; "
                      "cat /data/lidar-kiosk-mic-keeper.log 2>/dev/null || true; "
                      "cat /data/lidar-kiosk-buttons.log 2>/dev/null || true'")
        if ("mic_worker_rc=0 button_worker_rc=0" in report and
                "event=PACKAGE_PATH_READY" in report and
                "KEY_FORWARDER_READY forever" in report):
            print("KIOSK_WORKERS_READY_AFTER_REBOOT", flush=True)
            return
        if time.monotonic() > deadline:
            raise RuntimeError("The Kiosk microphone or button worker did not start")
        time.sleep(2)


def verify_gate(network: bool, install_kiosk: bool) -> None:
    deadline = time.monotonic() + 90
    while True:
        try:
            preference = adb("shell", "settings", "get", "global", "wifi_on")
            probe = subprocess.run(["adb", "-d", "shell", "ip", "-4", "addr",
                                    "show", "wlan0"], capture_output=True, text=True,
                                   timeout=15)
        except (RuntimeError, subprocess.TimeoutExpired):
            # USB ADB can briefly restart after sys.boot_completed becomes 1.
            preference = ""
            probe = None
        # Android may report boot complete before its WiFi interface exists.
        address = probe.stdout if probe is not None and probe.returncode == 0 else ""
        if preference == "0" and re.search(r"\binet\s+\d+\.\d+\.\d+\.\d+", address):
            break
        if time.monotonic() > deadline:
            raise RuntimeError("Gate did not return WiFi with next-boot preference off")
        time.sleep(2)
    boot_count = adb_read("shell", "settings", "get", "global", "boot_count")
    fixed = ("/system/bin/sh -c 'cat " + READY + "; "
             "/system/bin/iptables -t mangle -C OUTPUT -j L2EG4 && "
             "/system/bin/ip6tables -t mangle -C OUTPUT -j L2EG6 && echo GATE_HOOKS_OK'")
    report = root_read(fixed)
    kiosk_uid = package_uid(KIOSK, postboot=True) if install_kiosk else 0
    if (f"boot_count={boot_count}\nmode=continuous\nfilter=ready\n" not in report or
            f"kiosk_uid={kiosk_uid}\n" not in report or
            "GATE_HOOKS_OK" not in report):
        raise RuntimeError("Current-boot WiFi gate markers or hooks differ")
    if install_kiosk:
        assigned = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", address)
        if not assigned:
            raise RuntimeError("Kiosk web subnet could not be identified")
        interface = ipaddress.ip_interface(assigned.group(1))
        subnet = interface.network
        if not subnet.is_private:
            raise RuntimeError("Kiosk web access requires a private WiFi subnet")
        root_read("/system/bin/iptables -C INPUT -i wlan0 "
                  f"-s {subnet} -p tcp --dport 2324 -j ACCEPT")
        print(f"KIOSK_WEB_LAN_READY: http://{interface.ip}:2324/", flush=True)
    if network:
        if adb_read("shell", "getprop", "ro.adb.secure") != "1":
            raise RuntimeError("WiFi ADB is not in authenticated mode")
        port_deadline = time.monotonic() + 90
        while adb_read("shell", "getprop", "service.adb.tcp.port") != "5555":
            if time.monotonic() > port_deadline:
                raise RuntimeError("Authenticated WiFi ADB listener is absent")
            time.sleep(2)
        address = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", address).group(1)
        endpoint = address + ":5555"
        usb = adb_read("get-serialno")
        connect_deadline = time.monotonic() + 90
        while True:
            try:
                run("adb", "connect", endpoint)
                remote = run("adb", "-s", endpoint, "shell", "getprop", "ro.serialno")
                device = run("adb", "-s", endpoint, "shell", "getprop", "ro.product.device")
                identity = run("adb", "-s", endpoint, "shell", "id", "-u")
            except RuntimeError:
                if time.monotonic() > connect_deadline:
                    raise RuntimeError("Authenticated WiFi ADB did not become ready") from None
                time.sleep(2)
                continue
            if usb != remote or device != "lidar" or identity != "2000":
                raise RuntimeError("WiFi ADB does not identify as the selected Echo")
            break
        print(f"WiFi ADB reconnect: adb connect {endpoint}", flush=True)
        print(f"WiFi ADB shell: adb -s {endpoint} shell", flush=True)
    print("GATE_READY_AFTER_REBOOT: WiFi is up behind current-boot filters", flush=True)
