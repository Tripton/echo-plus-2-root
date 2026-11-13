#!/usr/bin/env python3
"""Guarded one-time installation after the checked RAM BootROM handoff.

The main() calls below are the reading order. Without --run, only local files
are checked. With --run, the script expects the Plus 2's temporary USB root
recovery from ../run.py, writes ordinary files in /data, then continues into
signed stock Android and registers the self-signed app with Package Manager.
It never issues raw eMMC read, write or erase commands.

The NS6575/8338N slot-A path completed an installation and cold-boot root
check on 2 November 2026. Other exact-image paths need device validation.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

from build import (INPUTS, NS65741_8149N_INPUTS, OUTPUTS,
                   POLICY_LOADER_RUNTIME_SHA256,
                   NS65741_8149N_POLICY_LOADER_RUNTIME_SHA256,
                   check_captured, check_switchroot_elf, patch_mtp_usb,
                   policy_runtime_sha256,
                   replace_once, TCP_ADB_ON, TCP_ADB_OFF,
                   USB_DISABLE_TRIGGER, USB_INERT_TRIGGER)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from firmware_profiles import NS65741_8149N, NS6575_8338N, by_name


ROOT = Path(__file__).resolve().parent
PERSISTENCE = ROOT.parents[1] / "persistence"
PACKAGE = "org.local.lidar.binderprobe"
PROMPT = b"android:/ # "
TOYBOX = "/system_root/system/bin/toybox"
REMOTE = {
    "policy_loader": "/dev/lidar-policy-loader",
    "safe_usb": "/dev/lidar-safe-usb.rc",
    "preserve_usb": "/dev/lidar-preserve-usb.rc",
    "switchroot": "/dev/lidar-switchroot",
    "helper": "/dev/lidar-root-helper",
    "key": "/dev/lidar-adb-pubkey",
    "readback": "/dev/lidar-readback",
}
STAGE_HELPER = "/data/x.stage-lidar"
STAGE_KEY = "/data/misc/adb/adb_keys.stage-lidar"
FINAL_KEY = "/data/misc/adb/adb_keys"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_file(path: Path, size: int, expected_sha: str) -> bytes:
    data = path.read_bytes()
    if len(data) != size or digest(data) != expected_sha:
        raise RuntimeError(f"checked input differs: {path}")
    return data


def command(args: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} {args[1]} failed: {(result.stdout + result.stderr)[-300:]}")
    return result.stdout.strip()


def adb(args: argparse.Namespace, *items: str, timeout: int = 30) -> str:
    return command([str(args.adb), "-d", *items], timeout=timeout)


def adb_bytes(args: argparse.Namespace, *items: str, timeout: int = 30) -> bytes:
    result = subprocess.run([str(args.adb), "-d", *items], capture_output=True,
                            timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"adb {items[0]} failed: {result.stderr[-250:]!r}")
    return result.stdout


def kernel_serial_from_cmdline(args: argparse.Namespace) -> str:
    cmdline = adb(args, "shell", "cat /proc/cmdline")
    match = re.search(r"(?:^|\s)androidboot\.serialno=([A-Z0-9]{12,24})(?=\s|$)", cmdline)
    if not match or "androidboot.hardware=mt8167" not in cmdline.split():
        raise RuntimeError("USB Echo kernel identity is missing or differs")
    return match.group(1)


def adb_usb_serial(args: argparse.Namespace) -> str:
    serial = kernel_serial_from_cmdline(args)
    reported = adb(args, "get-serialno")
    if reported and reported != serial:
        raise RuntimeError("USB ADB and kernel serials differ")
    return serial


def local_preflight(args: argparse.Namespace) -> dict[str, bytes]:
    """1. Check the exact image and every file to be sent to the device."""
    profile = by_name(args.profile)
    exact_inputs = (INPUTS if profile == NS6575_8338N else
                    NS65741_8149N_INPUTS if profile == NS65741_8149N else None)
    expected_runtime = (POLICY_LOADER_RUNTIME_SHA256 if profile == NS6575_8338N else
                        NS65741_8149N_POLICY_LOADER_RUNTIME_SHA256
                        if profile == NS65741_8149N else None)
    manifest = json.loads((args.built_dir / "manifest.json").read_text())
    if manifest.get("profile") != profile.name or set(manifest) != {
            "profile", "inputs", "outputs", "policy_loader_runtime"}:
        raise RuntimeError("stock transition manifest has another profile or layout")
    input_paths = {"policy": args.policy, "stock_usb_rc": args.stock_usb_rc,
                   "generic_usb_rc": args.generic_usb_rc}
    for name, path in input_paths.items():
        if exact_inputs is None:
            check_captured(path.read_bytes(), name)
        if digest(path.read_bytes()) != manifest["inputs"].get(name):
            raise RuntimeError(f"stock transition input differs from its build: {name}")
    if exact_inputs is None:
        safe = patch_mtp_usb(replace_once(args.stock_usb_rc.read_bytes(),
                                          TCP_ADB_ON, TCP_ADB_OFF, "stock TCP ADB"))
        preserve = replace_once(args.generic_usb_rc.read_bytes(),
                                USB_DISABLE_TRIGGER, USB_INERT_TRIGGER,
                                "generic USB disable trigger")
        if ((args.built_dir / "safe-usb.rc").read_bytes() != safe or
                (args.built_dir / "preserve-usb.rc").read_bytes() != preserve):
            raise RuntimeError("captured USB edits differ from the built RAM copies")
    files = {
        "policy": (checked_file(args.policy, *exact_inputs["policy"])
                   if exact_inputs else args.policy.read_bytes()),
        "stock_usb": (checked_file(args.stock_usb_rc, *exact_inputs["stock_usb_rc"])
                      if exact_inputs else args.stock_usb_rc.read_bytes()),
        "generic_usb": (checked_file(args.generic_usb_rc, *exact_inputs["generic_usb_rc"])
                        if exact_inputs else args.generic_usb_rc.read_bytes()),
        "safe_usb": (checked_file(args.built_dir / "safe-usb.rc", *OUTPUTS["safe-usb.rc"])
                     if exact_inputs else (args.built_dir / "safe-usb.rc").read_bytes()),
        "preserve_usb": (checked_file(args.built_dir / "preserve-usb.rc", *OUTPUTS["preserve-usb.rc"])
                         if exact_inputs else (args.built_dir / "preserve-usb.rc").read_bytes()),
        "switchroot": check_switchroot_elf((args.built_dir / "switchroot.elf").read_bytes()),
        "helper": checked_file(args.helper, args.helper.stat().st_size, args.helper_sha256),
        "apk": checked_file(args.apk, args.apk.stat().st_size, args.apk_sha256),
    }
    loader = (args.built_dir / "policy-loader.elf").read_bytes()
    if policy_runtime_sha256(loader) != manifest["policy_loader_runtime"] or (
            expected_runtime is not None and
            policy_runtime_sha256(loader) != expected_runtime):
        raise RuntimeError("policy loader runtime image differs from its checked build")
    files["policy_loader"] = loader
    if (set(manifest["inputs"]) != set(input_paths) or
            set(manifest["outputs"]) != {"policy-loader.elf", "switchroot.elf",
                                         "safe-usb.rc", "preserve-usb.rc"} or
            any(digest(files[name]) != manifest["outputs"][filename]
                for filename, name in (("policy-loader.elf", "policy_loader"),
                                       ("switchroot.elf", "switchroot"),
                                       ("safe-usb.rc", "safe_usb"),
                                       ("preserve-usb.rc", "preserve_usb")))):
        raise RuntimeError("stock transition manifest differs from its files")
    key = args.adb_pubkey.read_bytes()
    if not (200 <= len(key) <= 8192 and key.isascii() and
            b"\x00" not in key and len(key.splitlines()) == 1):
        raise RuntimeError("ADB public key has an unexpected format")
    files["key"] = key
    command([str(args.apksigner), "verify", "--min-sdk-version", "23", str(args.apk)])
    badging = command([str(args.aapt), "dump", "badging", str(args.apk)])
    if not re.search(r"^package: name='org\.local\.lidar\.binderprobe' versionCode='1' versionName='1\.0\.0'", badging, re.M):
        raise RuntimeError("signed APK package or version differs")
    print(f"PREFLIGHT_INSTALL_INPUTS_OK: {profile.name} slot {args.slot.upper()} and signed app", flush=True)
    return files


def serial_command(port, line: str, *, timeout: int = 8) -> str:
    port.reset_input_buffer()
    port.write(line.encode("ascii") + b"\n")
    output = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output.extend(port.read(4096))
        if PROMPT in output:
            break
    if PROMPT not in output:
        raise RuntimeError(f"recovery serial prompt absent after {line.split()[0]}")
    return bytes(output).decode("utf-8", "replace").replace("\r", "")


def serial_checked(port, line: str, label: str, *, timeout: int = 20) -> str:
    answer = serial_command(port, f"{line}; echo LIDAR_{label}_EXIT=$?", timeout=timeout)
    if not re.search(rf"(?:^|\n)LIDAR_{label}_EXIT=0(?:\n|$)", answer):
        raise RuntimeError(f"recovery command failed: {label}")
    return answer


def verify_recovery(args: argparse.Namespace, files: dict[str, bytes]):
    """2. Require this one USB device and the known temporary root layout."""
    import serial
    from serial.tools import list_ports

    if adb(args, "get-state") != "recovery" or kernel_serial_from_cmdline(args) != args.target_serial:
        raise RuntimeError("USB ADB is not the selected Plus 2 recovery")
    for remote, local in (("/system_root/sepolicy", "policy"),
                          ("/system_root/init.mt8167.usb.rc", "stock_usb"),
                          ("/system_root/init.usb.rc", "generic_usb")):
        if adb_bytes(args, "exec-out", "cat", remote) != files[local]:
            raise RuntimeError(f"live stock input differs: {remote}")
    profile = by_name(args.profile)
    fingerprints = []
    for path in ("/system_root/system/build.prop", "/system_root/build.prop"):
        try:
            properties = adb_bytes(args, "exec-out", "cat", path, timeout=10)
        except RuntimeError:
            continue
        fingerprints.extend(re.findall(rb"(?m)^ro\.build\.fingerprint=(.+)$", properties))
    if not fingerprints or set(fingerprints) != {profile.fingerprint.encode("ascii")}:
        raise RuntimeError("mounted stock system fingerprint is not the selected boot image")
    symbols = adb_bytes(args, "exec-out", "cat", "/proc/kallsyms", timeout=20)
    matches = re.findall(rb"(?m)^([0-9a-f]{16}) [tT] sel_read_enforce$", symbols)
    if matches != [f"{profile.sel_read_enforce:016x}".encode("ascii")]:
        raise RuntimeError("running kernel address differs from the selected image")
    ports = [p for p in list_ports.comports() if (p.vid, p.pid) == (0x0E8D, 0x2007)]
    if len(ports) != 1:
        raise RuntimeError("expected exactly one Plus 2 recovery serial port")
    port = serial.Serial(ports[0].device, 115200, timeout=0.2, write_timeout=2)
    try:
        if "uid=0(root) gid=0(root)" not in serial_command(port, "id"):
            raise RuntimeError("temporary recovery shell is not UID 0")
        if args.target_serial not in serial_command(port, "cat /proc/cmdline"):
            raise RuntimeError("recovery cmdline identity differs")
        if "CapEff:\t0000003fffffffff" not in serial_command(port, "cat /proc/1/status"):
            raise RuntimeError("temporary PID 1 lacks the tested capabilities")
        mounts = serial_command(port, "cat /proc/mounts")
        system_partition = 13 if args.slot == "a" else 14
        if (f"/dev/mmcblk0p{system_partition} /system_root ext4 ro," not in mounts or
                "norecovery" not in mounts):
            raise RuntimeError("read-only stock system mount differs")
        if " /data " in mounts:
            raise RuntimeError("userdata was unexpectedly mounted before staging")
        if not re.search(r"\b4987375\s+mmcblk0p16\b", serial_command(port, "cat /proc/partitions")):
            raise RuntimeError("userdata partition size or number differs")
        print("CHECKPOINT_INSTALL_RECOVERY_ROOT_OK", flush=True)
        return port
    except Exception:
        port.close()
        raise


def upload_recovery_files(args: argparse.Namespace, files: dict[str, bytes]) -> None:
    """3. Place only volatile copies under recovery /dev and read them back."""
    paths = {
        "policy_loader": args.built_dir / "policy-loader.elf",
        "safe_usb": args.built_dir / "safe-usb.rc",
        "preserve_usb": args.built_dir / "preserve-usb.rc",
        "switchroot": args.built_dir / "switchroot.elf",
        "helper": args.helper,
        "key": args.adb_pubkey,
    }
    for name, path in paths.items():
        adb(args, "push", str(path), REMOTE[name], timeout=45)
        if adb_bytes(args, "exec-out", "cat", REMOTE[name], timeout=45) != files[name]:
            raise RuntimeError(f"volatile upload readback differs: {name}")
    print("CHECKPOINT_INSTALL_VOLATILE_UPLOADS_OK", flush=True)


def load_stock_policy(port, policy_size: int, *, force: bool = False) -> None:
    """4. Restore the checked stock policy in recovery RAM before /data."""
    mounts = serial_command(port, "cat /proc/mounts")
    if "selinuxfs /sys/fs/selinux selinuxfs" not in mounts:
        serial_checked(port, "mount -t selinuxfs selinuxfs /sys/fs/selinux", "SELINUX_MOUNT")
    loaded_size = serial_command(port, "cat /sys/fs/selinux/policy | wc -c")
    if force or not re.search(rf"\b{policy_size}\b", loaded_size):
        serial_checked(port, f"chmod 0700 {REMOTE['policy_loader']}", "POLICY_CHMOD")
        result = serial_checked(port, REMOTE["policy_loader"], "POLICY_LOAD")
        if f"POLICY_LOAD_SINGLE_WRITE_OK bytes={policy_size}" not in result:
            raise RuntimeError("stock policy loader did not confirm one write")
    if not re.search(rf"\b{policy_size}\b", serial_command(port, "cat /sys/fs/selinux/policy | wc -c")):
        raise RuntimeError("loaded stock policy size differs")
    if not re.search(r"(?:^|\n)0\n", serial_command(port, "cat /sys/fs/selinux/enforce; echo")):
        raise RuntimeError("recovery policy is not permissive")
    print("CHECKPOINT_INSTALL_STOCK_POLICY_RAM_OK", flush=True)


def readback_data(args: argparse.Namespace, port, source: str, expected_sha: str) -> None:
    serial_checked(port, f"{TOYBOX} cp {source} {REMOTE['readback']}", "READBACK_COPY")
    try:
        # Pull through the recovery USB daemon, as in the measured research
        # path. The serial shell and ADB must agree on the actual file bytes.
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "readback"
            adb(args, "pull", REMOTE["readback"], str(local), timeout=45)
            if digest(local.read_bytes()) != expected_sha:
                raise RuntimeError(f"data file readback differs: {source}")
    finally:
        serial_checked(port, f"rm -f {REMOTE['readback']}", "READBACK_REMOVE")


def require_label(port, path: str, label: str) -> None:
    """Check the label actually stored on ext4, not merely chcon's exit code."""
    if label not in serial_command(port, f"ls -Z {path}"):
        raise RuntimeError(f"SELinux label differs: {path}")


def stage_userdata(args: argparse.Namespace, port, files: dict[str, bytes]) -> None:
    """5. Commit only the helper and public ADB key as ordinary /data files."""
    created_node = False
    mounted = False
    empty_targets_checked = False
    try:
        if "No such file" in serial_command(port, "ls -l /dev/mmcblk0p16"):
            serial_checked(port, "mknod /dev/mmcblk0p16 b 179 16", "DATA_NODE")
            created_node = True
        serial_checked(port, "mount -t ext4 -o rw /dev/mmcblk0p16 /data", "DATA_MOUNT", timeout=30)
        mounted = True
        if " /data ext4 rw," not in serial_command(port, "cat /proc/mounts"):
            raise RuntimeError("userdata read-write mount not confirmed")
        for path in ("/data/x", STAGE_HELPER, FINAL_KEY, STAGE_KEY):
            serial_checked(port, f"test ! -e {path}", "TARGET_FREE")
        empty_targets_checked = True
        serial_checked(port, f"{TOYBOX} mkdir -p /data/misc/adb", "KEY_DIR")
        serial_checked(port, f"{TOYBOX} chown 1000:2000 /data/misc/adb", "KEY_DIR_OWNER")
        serial_checked(port, f"{TOYBOX} chmod 2750 /data/misc/adb", "KEY_DIR_MODE")
        serial_checked(port, f"{TOYBOX} cp {REMOTE['key']} {STAGE_KEY}", "KEY_COPY")
        serial_checked(port, f"{TOYBOX} chown 1000:2000 {STAGE_KEY}", "KEY_OWNER")
        serial_checked(port, f"{TOYBOX} chmod 0640 {STAGE_KEY}", "KEY_MODE")
        serial_checked(port, f"{TOYBOX} chcon u:object_r:adb_keys_file:s0 {STAGE_KEY}", "KEY_LABEL")
        require_label(port, STAGE_KEY, "u:object_r:adb_keys_file:s0")
        readback_data(args, port, STAGE_KEY, digest(files["key"]))
        serial_checked(port, f"{TOYBOX} cp {REMOTE['helper']} {STAGE_HELPER}", "HELPER_COPY")
        serial_checked(port, f"{TOYBOX} chown 0:0 {STAGE_HELPER}", "HELPER_OWNER")
        serial_checked(port, f"{TOYBOX} chmod 0700 {STAGE_HELPER}", "HELPER_MODE")
        serial_checked(port, f"{TOYBOX} chcon u:object_r:init_exec:s0 {STAGE_HELPER}", "HELPER_LABEL")
        require_label(port, STAGE_HELPER, "u:object_r:init_exec:s0")
        readback_data(args, port, STAGE_HELPER, args.helper_sha256)
        serial_checked(port, f"{TOYBOX} mv {STAGE_KEY} {FINAL_KEY}", "KEY_COMMIT")
        serial_checked(port, f"{TOYBOX} mv {STAGE_HELPER} /data/x", "HELPER_COMMIT")
        serial_checked(port, "sync", "DATA_SYNC", timeout=30)
        readback_data(args, port, FINAL_KEY, digest(files["key"]))
        readback_data(args, port, "/data/x", args.helper_sha256)
        require_label(port, FINAL_KEY, "u:object_r:adb_keys_file:s0")
        require_label(port, "/data/x", "u:object_r:init_exec:s0")
        print("CHECKPOINT_INSTALL_USERDATA_HELPER_AND_KEY_OK", flush=True)
        empty_targets_checked = False
    except Exception:
        if mounted and empty_targets_checked:
            for path in (STAGE_HELPER, STAGE_KEY, "/data/x", FINAL_KEY):
                serial_checked(port, f"rm -f {path}", "ROLLBACK_REMOVE")
            serial_checked(port, "sync", "ROLLBACK_SYNC", timeout=30)
            print("CHECKPOINT_INSTALL_USERDATA_ROLLBACK_OK", flush=True)
        raise
    finally:
        if mounted:
            serial_checked(port, "umount /data", "DATA_UNMOUNT", timeout=30)
        if created_node:
            serial_checked(port, "rm -f /dev/mmcblk0p16", "DATA_NODE_REMOVE")


def continue_stock_android(args: argparse.Namespace, port, files: dict[str, bytes]) -> None:
    """6. Bind the checked RAM init scripts, self-test, then exec stock init."""
    for name in ("safe_usb", "preserve_usb"):
        serial_checked(port, f"chmod 0644 {REMOTE[name]}", f"{name.upper()}_CHMOD")
    serial_checked(port, f"chmod 0755 {REMOTE['switchroot']}", "SWITCHROOT_CHMOD")
    if "No such file" in serial_command(port, "ls -ld /dev/socket"):
        serial_checked(port, "mkdir /dev/socket", "SOCKET_DIR")
        serial_checked(port, "chmod 0755 /dev/socket", "SOCKET_MODE")
    targets = (("safe_usb", "/system_root/init.mt8167.usb.rc"),
               ("preserve_usb", "/system_root/init.usb.rc"))
    mounts = serial_command(port, "cat /proc/mounts")
    for _, target in targets:
        if f" {target} " in mounts:
            raise RuntimeError(f"unexpected prior bind mount: {target}")
    for name, target in targets:
        serial_checked(port, f"mount -o bind {REMOTE[name]} {target}", f"{name.upper()}_BIND")
        if adb_bytes(args, "exec-out", "cat", target) != files[name]:
            raise RuntimeError(f"RAM bind readback differs: {name}")
    selftest = serial_checked(port, f"{REMOTE['switchroot']} --selftest", "SWITCHROOT_SELFTEST")
    for marker in ("LIDAR_SWITCHROOT_UNSHARE_OK", "LIDAR_SWITCHROOT_MOUNTS_OK",
                   "LIDAR_SWITCHROOT_ROOT_OK"):
        if marker not in selftest:
            raise RuntimeError(f"switchroot self-test omitted {marker}")
    print("CHECKPOINT_INSTALL_STOCK_INIT_HANDOFF_READY_OK", flush=True)
    port.reset_input_buffer()
    port.write(f"exec {REMOTE['switchroot']}\n".encode("ascii"))
    port.flush()
    # Keep the port open until switchroot itself responds. A host-side flush
    # only drains the local write buffer; closing immediately can leave PID 1
    # waiting at its shell prompt with the command never executed.
    from serial import SerialException

    answer = bytearray()
    deadline = time.monotonic() + 20
    disconnected = False
    while time.monotonic() < deadline:
        try:
            answer.extend(port.read(4096))
        except SerialException:
            # switchroot replaces recovery init and USB can re-enumerate.
            disconnected = True
            break
        if b"LIDAR_SWITCHROOT_INIT_FAIL" in answer:
            raise RuntimeError("stock init handoff failed inside switchroot")
        if b"LIDAR_SWITCHROOT_ROOT_OK" in answer:
            break
    else:
        raise RuntimeError("stock init handoff was not acknowledged by recovery PID 1")
    if not disconnected and b"LIDAR_SWITCHROOT_ROOT_OK" not in answer:
        raise RuntimeError("stock init handoff ended without switchroot confirmation")
    print("STOCK_INIT_HANDOFF_ATTEMPT: wait for signed stock Android", flush=True)


def wait_for_stock(args: argparse.Namespace) -> None:
    """7. Distinguish stock Android and Package Manager from USB upload."""
    started = time.monotonic()
    deadline = started + 360
    next_notice = started + 30
    while time.monotonic() < deadline:
        try:
            if adb_usb_serial(args) == args.target_serial and \
               adb(args, "shell", "getprop", "sys.boot_completed", timeout=5) == "1" and \
               adb(args, "shell", "pidof", "system_server", timeout=5).isdigit() and \
               "found" in adb(args, "shell", "service", "check", "package", timeout=5):
                break
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        if time.monotonic() >= next_notice:
            print(f"Still waiting for stock Android ({int(time.monotonic() - started)} seconds elapsed)...",
                  flush=True)
            next_notice += 30
        time.sleep(2)
    else:
        raise RuntimeError("stock Android Package Manager did not become ready")
    profile = by_name(args.profile)
    if adb(args, "shell", "getprop", "ro.build.fingerprint") != profile.fingerprint:
        raise RuntimeError("stock Android fingerprint differs from the checked build")
    if adb(args, "shell", "getprop", "ro.boot.slot_suffix") != "_" + args.slot:
        raise RuntimeError("stock Android is not running the selected boot slot")
    print("CHECKPOINT_INSTALL_SIGNED_STOCK_AND_PM_OK", flush=True)


def verify_staged_userdata(args: argparse.Namespace, files: dict[str, bytes]) -> None:
    """Check the files written before stock init in its current mount namespace."""
    helper = "/proc/1/root/data/x"
    key = "/proc/1/root/data/misc/adb/adb_keys"
    if adb_bytes(args, "exec-out", "cat", helper) != files["helper"]:
        raise RuntimeError("stock userdata helper differs from the checked binary")
    if adb_bytes(args, "exec-out", "cat", key) != files["key"]:
        raise RuntimeError("stock userdata ADB key differs from this host")
    if "u:object_r:init_exec:s0" not in adb(args, "shell", "ls", "-Z", helper):
        raise RuntimeError("stock userdata helper label differs")
    if "u:object_r:adb_keys_file:s0" not in adb(args, "shell", "ls", "-Z", key):
        raise RuntimeError("stock userdata ADB key label differs")
    print("CHECKPOINT_INSTALL_STOCK_USERDATA_READBACK_OK", flush=True)


def app_stopped_on_disk(args: argparse.Namespace) -> bool:
    """Read Package Manager's saved state through stock init's mount namespace."""
    path = "/proc/1/root/data/system/users/0/package-restrictions.xml"
    restrictions = ET.fromstring(adb_bytes(args, "exec-out", "cat", path))
    matches = [entry for entry in restrictions.iter("pkg")
               if entry.get("name") == PACKAGE]
    if len(matches) != 1:
        raise RuntimeError("installed app is absent or duplicated in saved package state")
    return matches[0].get("stopped") == "true"


def activate_app_for_next_boot(args: argparse.Namespace, budget: str,
                               expected_budget: bytes) -> None:
    """Start the app without exploit flags, then verify durable unstopped state."""
    # ProbeService returns immediately without both exact exploit flags and a
    # boot-receiver source. Starting it clears Android's stopped-package state.
    result = adb(args, "shell", "am", "startservice", "-n",
                 f"{PACKAGE}/.ProbeService", timeout=30)
    if "Starting service:" not in result or "Error:" in result:
        raise RuntimeError("no-op app activation failed: " + result)
    deadline = time.monotonic() + 60
    while app_stopped_on_disk(args):
        if time.monotonic() >= deadline:
            raise RuntimeError("installed app remained stopped on disk")
        time.sleep(2)
    adb(args, "shell", "sync")
    if app_stopped_on_disk(args):
        raise RuntimeError("installed app reverted to stopped after sync")
    status = adb(args, "shell", "dumpsys", "package", PACKAGE, timeout=40)
    if not re.search(r"User 0:.*installed=true.*stopped=false", status):
        raise RuntimeError("saved and live package states disagree")
    if adb_bytes(args, "exec-out", "cat", budget) != expected_budget:
        raise RuntimeError("no-op activation changed the root-attempt budget")
    print("CHECKPOINT_INSTALL_APP_ACTIVE_ON_DISK_OK", flush=True)


def install_and_arm_app(args: argparse.Namespace, files: dict[str, bytes]) -> None:
    """8. Register the signed APK and allow ten attempts on separate boots."""
    # This is an initial install, never an upgrade of an app-controlled tree.
    installed = adb(args, "shell", "pm", "list", "packages", PACKAGE).splitlines()
    if f"package:{PACKAGE}" not in installed:
        result = adb(args, "install", str(args.apk), timeout=120)
        if "Success" not in result:
            raise RuntimeError("Package Manager did not confirm the app install")
    paths = adb(args, "shell", "pm", "path", PACKAGE).splitlines()
    if len(paths) != 1 or not paths[0].startswith("package:/data/app/"):
        raise RuntimeError("Package Manager path differs after install")
    details = adb(args, "shell", "dumpsys", "package", PACKAGE, timeout=40)
    if "versionCode=1 " not in details or "versionName=1.0.0" not in details:
        raise RuntimeError("Package Manager version differs after install")
    # Recovery adbd may retain its old mount namespace. A pull of base.apk
    # can therefore fail even though Package Manager sees the new package.
    remote_apk = "/proc/1/root" + paths[0].removeprefix("package:")
    try:
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "readback.apk"
            adb(args, "pull", remote_apk, str(local), timeout=60)
            if digest(local.read_bytes()) != digest(files["apk"]):
                raise RuntimeError("installed APK readback differs")
        print("CHECKPOINT_INSTALL_APK_READBACK_OK", flush=True)
    except RuntimeError as error:
        if "remote object" not in str(error) or "does not exist" not in str(error):
            raise
        print("CHECKPOINT_INSTALL_APK_PM_ONLY: old adbd mount namespace", flush=True)
    # The app's service is intentionally not exported. Package Manager creates
    # the app-data root, while getFilesDir() normally creates files/ lazily.
    # The temporary root ADB creates that private directory and one-byte budget
    # with the Package Manager-assigned owner and SELinux MCS label. A fresh
    # install prevents an old app-controlled symlink from redirecting the write.
    # Subsequent boots rearm through the app after UID-0 proof.
    if adb(args, "shell", "id", "-u") != "0":
        raise RuntimeError("temporary stock ADB no longer has UID 0")
    # Recovery adbd survives the stock-init handoff in its old mount namespace.
    # PID 1's root exposes the live /data that Package Manager just mounted.
    # /data/user/0 is an absolute symlink to /data/data. Resolve its real
    # target inside PID 1's root; following the symlink from old adbd does not.
    app_data = f"/proc/1/root/data/data/{PACKAGE}"
    files_dir = f"{app_data}/files"
    budget = f"{files_dir}/autoroot_budget_v146"
    staged_budget = budget + ".stage-lidar"
    owner = adb(args, "shell", "stat", "-c", "%u:%g", app_data)
    if not re.fullmatch(r"[0-9]+:[0-9]+", owner) or int(owner.split(":")[0]) < 10000:
        raise RuntimeError("Package Manager app-data owner is invalid")
    label = adb(args, "shell", "ls", "-Zd", app_data).split()[0]
    if not re.fullmatch(r"u:object_r:app_data_file:s0(?::c[0-9]+(?:,c[0-9]+)*)?", label):
        raise RuntimeError("Package Manager app-data SELinux label differs")
    # A broadcast can clear the stopped flag while `am` is still waiting for
    # its result. If the host times out after that point, a resumed install
    # must verify the completed work rather than trying to create it again.
    armed = adb(args, "shell", f"if test -f {budget} && test ! -L {budget}; then echo yes; fi")
    if armed == "yes":
        adb(args, "shell", f"test -d {files_dir} && test ! -L {files_dir}")
        existing_budget = adb_bytes(args, "exec-out", "cat", budget)
        if (adb(args, "shell", "stat", "-c", "%u:%g:%a", files_dir) != owner + ":700"
                or adb(args, "shell", "ls", "-Zd", files_dir).split()[0] != label
                or existing_budget not in {str(value).encode("ascii") for value in range(1, 11)}
                or adb(args, "shell", "stat", "-c", "%u:%g:%a", budget) != owner + ":600"
                or adb(args, "shell", "ls", "-Z", budget).split()[0] != label):
            raise RuntimeError("existing root-attempt budget content, owner, mode or label differs")
        activate_app_for_next_boot(args, budget, existing_budget)
        print("CHECKPOINT_INSTALL_APP_ARMED_FOR_STOCK_BOOT_OK: verified existing install", flush=True)
        return
    adb(args, "shell", f"test ! -e {files_dir} && test ! -L {files_dir}")
    adb(args, "shell", "mkdir", files_dir)
    adb(args, "shell", "chown", owner, files_dir)
    adb(args, "shell", "chmod", "0700", files_dir)
    adb(args, "shell", "chcon", label, files_dir)
    if (adb(args, "shell", "stat", "-c", "%u:%g", files_dir) != owner
            or adb(args, "shell", "ls", "-Zd", files_dir).split()[0] != label):
        raise RuntimeError("app files directory owner or SELinux label differs")
    adb(args, "shell", f"test ! -e {budget} && test ! -L {budget} && test ! -e {staged_budget} && test ! -L {staged_budget}")
    adb(args, "shell", f"printf 10 > {staged_budget}")
    adb(args, "shell", "chown", owner, staged_budget)
    adb(args, "shell", "chmod", "0600", staged_budget)
    adb(args, "shell", "chcon", label, staged_budget)
    if (adb_bytes(args, "exec-out", "cat", staged_budget) != b"10"
            or adb(args, "shell", "stat", "-c", "%u:%g", staged_budget) != owner
            or adb(args, "shell", "ls", "-Zd", staged_budget).split()[0] != label):
        raise RuntimeError("staged root-attempt budget content, owner or label differs")
    adb(args, "shell", "mv", staged_budget, budget)
    if (adb_bytes(args, "exec-out", "cat", budget) != b"10"
            or adb(args, "shell", "stat", "-c", "%u:%g", budget) != owner
            or adb(args, "shell", "ls", "-Zd", budget).split()[0] != label):
        raise RuntimeError("root-attempt budget content, owner or label differs")
    activate_app_for_next_boot(args, budget, b"10")
    print("CHECKPOINT_INSTALL_APP_ARMED_FOR_STOCK_BOOT_OK", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--stock-usb-rc", type=Path, required=True)
    parser.add_argument("--generic-usb-rc", type=Path, required=True)
    parser.add_argument("--built-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--helper", type=Path,
                        default=PERSISTENCE / "helper/build/core_helper64")
    parser.add_argument("--helper-sha256", required=True,
                        help="SHA-256 of the helper built from this checkout")
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--adb-pubkey", type=Path, required=True)
    parser.add_argument("--adb", default=shutil.which("adb") or "adb")
    parser.add_argument("--aapt", default=shutil.which("aapt") or "aapt")
    parser.add_argument("--apksigner", default=shutil.which("apksigner") or "apksigner")
    parser.add_argument("--target-serial", help="private expected USB serial; needed only with --run")
    parser.add_argument("--profile", required=True, help="selected exact boot-image profile")
    parser.add_argument("--slot", choices=("a", "b"), required=True)
    parser.add_argument("--run", action="store_true", help="perform persistent /data installation")
    parser.add_argument("--resume-stock", action="store_true",
                        help="finish app installation after a checked stock-init handoff")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.apk_sha256):
        raise SystemExit("STOP_INSTALL: --apk-sha256 must be 64 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{64}", args.helper_sha256):
        raise SystemExit("STOP_INSTALL: --helper-sha256 must be 64 lowercase hex characters")
    files = local_preflight(args)
    if args.run and args.resume_stock:
        raise SystemExit("STOP_INSTALL: select only one live installation mode")
    if not args.run and not args.resume_stock:
        print("PREFLIGHT_ONLY: no USB, serial or eMMC access", flush=True)
        return
    if not args.target_serial or not re.fullmatch(r"[A-Z0-9]{12,24}", args.target_serial):
        raise SystemExit("STOP_INSTALL: --target-serial is required for --run")
    if args.run:
        port = verify_recovery(args, files)
        try:
            upload_recovery_files(args, files)
            load_stock_policy(port, len(files["policy"]),
                              force=by_name(args.profile) != NS6575_8338N)
            stage_userdata(args, port, files)
            continue_stock_android(args, port, files)
        finally:
            port.close()
    wait_for_stock(args)
    verify_staged_userdata(args, files)
    install_and_arm_app(args, files)
    print("INSTALL_READY_FOR_COLD_BOOT: prove UID 0 after an ordinary power cycle", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"STOP_INSTALL: {error}")
