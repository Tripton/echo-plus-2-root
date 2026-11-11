#!/usr/bin/env python3
"""One-time volatile BootROM handoff for the pinned Echo Plus 2 image.

Read this file from main() downward after build.py. Running it is explicit:
without --run it only checks local files. It does not read, program or erase
eMMC blocks. A successful USB upload is not evidence that Android booted.
The later stock-init transition and APK installation are separate steps.
"""

import argparse
import hashlib
import logging
import re
import struct
import subprocess
import sys
from pathlib import Path

from build import OUTPUTS_BY_PROFILE_SLOT, PINNED, SOURCE, align, sha
from firmware_profiles import NS6575_8338N, by_name


PINNED_MTKCLIENT_REVISION = "7cb40e727727dfe3faa065eefb29b16ed29bbdf1"
STAGE_ADDRESSES = (
    (0x201000, "preloader_patched.bin"),
    (0x226000, "lk_bridge.bin"),
    (0x227000, "preloader_snapshot.bin"),
    (0x228000, "fdt_initrd.bin"),
    (0x229000, "handoff_cave.bin"),
)
SRAM_END = 0x238000


def checked_file(path: Path, length: int, digest: str) -> bytes:
    data = path.read_bytes()
    if len(data) != length or sha(data) != digest:
        raise ValueError(f"checked file changed: {path}")
    return data


def preflight(args: argparse.Namespace) -> list[tuple[int, bytes, str]]:
    # 1. Pin the external BootROM implementation and its Stage-1 payload.
    revision = subprocess.check_output(
        ["git", "-C", str(args.mtkclient_root), "rev-parse", "HEAD"],
        text=True).strip()
    dirty = subprocess.run(
        ["git", "-C", str(args.mtkclient_root), "diff", "--quiet", "HEAD"],
        check=False).returncode
    untracked_package_files = subprocess.check_output(
        ["git", "-C", str(args.mtkclient_root), "ls-files", "--others",
         "--exclude-standard", "--", "mtkclient"], text=True).strip()
    if (revision != PINNED_MTKCLIENT_REVISION or dirty != 0
            or untracked_package_files):
        raise ValueError("MTKClient source does not match the tested revision")
    stage1_size, stage1_hash = PINNED["stage1"]
    checked_file(args.stage1, stage1_size, stage1_hash)
    if not args.stage1.resolve().is_relative_to(args.mtkclient_root.resolve()):
        raise ValueError("Stage-1 file must belong to the checked MTKClient clone")

    # 2. Confirm every offline-generated file, even the two that are embedded
    # inside the handoff image. No firmware dump is read by this launcher.
    marker_path = args.built_dir / "firmware-profile.txt"
    if marker_path.exists():
        marker = marker_path.read_text()
        if marker.count("\n") != 1 or not marker.endswith("\n"):
            raise ValueError("RAM image profile marker is malformed")
        parts = marker.strip().split()
        if len(parts) == 1:
            # Only the original 8338N A build had a verified one-field marker.
            if parts[0] != NS6575_8338N.name:
                raise ValueError("legacy RAM image marker has no slot; rebuild from dump")
            parts.append("a")
        if len(parts) != 2 or parts[1] not in ("a", "b"):
            raise ValueError("RAM image profile marker is malformed")
        profile = by_name(parts[0])
        slot = parts[1]
    else:
        # Older, already-built 8338N directories have no marker. Their exact
        # payload hashes below still identify the sole tested profile.
        profile = by_name("NS6575-8338N")
        slot = "a"
    payload = {name: checked_file(args.built_dir / name, *expected)
               for name, expected in OUTPUTS_BY_PROFILE_SLOT[profile.name, slot].items()}
    if payload["fdt_initrd.bin"][1024:1024 + 2038] != payload["initramfs_overlay.cpio.gz"]:
        raise ValueError("embedded initramfs overlay differs")
    stages = []
    for address, name in STAGE_ADDRESSES:
        data = payload[name]
        if name == "fdt_initrd.bin":
            data += bytes(3072 - len(data))
        end = address + align(len(data), 512)
        if end > SRAM_END:
            raise ValueError(f"SRAM staging exceeds checked region: {name}")
        stages.append((address, data, name))
    for (address, data, name), (next_address, _, _) in zip(stages, stages[1:]):
        if address + align(len(data), 512) > next_address:
            raise ValueError(f"SRAM staging overlap after {name}")
    print(f"PREFLIGHT_BOOTSTRAP_RUN_OK: {profile.name} slot {slot.upper()} pinned payloads and SRAM layout", flush=True)
    return stages


def send_word(port, value: int) -> None:
    if not port.usbwrite(struct.pack(">I", value)):
        raise RuntimeError(f"Stage-1 USB write failed for 0x{value:08x}")


def upload(port, address: int, data: bytes, name: str) -> None:
    """Use MTKClient's Stage-1 SRAM protocol and require its ACK.

    Protocol reference: MTKClient ``mtk_main.py`` at the pinned revision.
    MTKClient and its payload are external GPLv3 dependencies.
    """
    padded = data + bytes(-len(data) % 512)
    if address < 0x201000 or address + len(padded) > SRAM_END:
        raise ValueError(f"out-of-range SRAM upload: {name}")
    for word in (0xF00DD00D, 0x4000, address, len(padded)):
        send_word(port, word)
    print(f"RAM_UPLOAD {name} address=0x{address:x} bytes={len(padded)}", flush=True)
    for index, byte in enumerate(padded):
        if not port.usbwrite(bytes((byte,))):
            raise RuntimeError(f"short SRAM upload: {name}+0x{index:x}")
        if index and index % 0x4000 == 0:
            print(f"RAM_PROGRESS {name} {index}/{len(padded)}", flush=True)
    if port.rdword() != 0xD0D0D0D0:
        raise RuntimeError(f"Stage-1 ACK differs after {name}")


def handoff(args: argparse.Namespace, stages: list[tuple[int, bytes, str]]) -> None:
    # 3. Only enter BootROM after a human explicitly supplied --run and a
    # locally stored ME_ID hash. The hash identifies this one physical unit;
    # it is never part of the public source or example configuration.
    if not args.target_meid_sha256 or not re.fullmatch(r"[0-9a-f]{64}", args.target_meid_sha256):
        raise ValueError("--target-meid-sha256 is required for --run")
    sys.path.insert(0, str(args.mtkclient_root))
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.Library.pltools import PLTools
    from mtkclient.config.mtk_config import MtkConfig

    config = MtkConfig(loglevel=logging.INFO)
    # Linux usbfs rejects the interface-recipient request used by the older
    # Kamakiri path. The upstream Kamakiri2 path was checked on this unit in
    # an Arch Linux ARM guest: Stage 1, RAM upload and root recovery completed.
    config.ptype = "kamakiri2" if sys.platform.startswith("linux") else "kamakiri"
    config.hwparam_path = str(args.built_dir)
    mtk = Mtk(config=config, loglevel=logging.INFO)
    try:
        print("WAIT_FOR_BOOTROM: power on the Plus 2 while holding Action", flush=True)
        if not mtk.preloader.init():
            raise RuntimeError("BootROM handshake failed")
        meid = mtk.config.meid
        identity_hash = (hashlib.sha256(bytes(meid)).hexdigest()
                         if isinstance(meid, (bytes, bytearray, memoryview)) else None)
        if (mtk.config.hwcode != 0x8167 or not mtk.config.is_brom or
                identity_hash != args.target_meid_sha256):
            raise RuntimeError("connected BootROM is not the checked Plus 2")
        print("CHECKPOINT_BOOTROM_ID_OK", flush=True)
        print("RELEASE_ACTION_NOW: BootROM identified", flush=True)

        # 4. Re-enter BootROM and ask upstream MTKClient to run its Kamakiri
        # Stage 1. This repository does not contain or claim that exploit.
        mtk = mtk.crasher()
        if mtk is None or mtk.port.cdc.pid != 0x0003:
            raise RuntimeError("BootROM did not reappear after crash")
        if not PLTools(mtk, logging.INFO).runpayload(str(args.stage1)):
            raise RuntimeError("upstream Stage-1 payload was rejected")
        print("CHECKPOINT_STAGE1_OK", flush=True)

        # 5. Place the checked preloader, LK bridge, snapshot helper, kernel
        # entry shim and Thumb cave in nonoverlapping SRAM regions.
        for address, data, name in stages:
            upload(mtk.port, address, data, name)
        print("CHECKPOINT_RAM_STAGED_OK", flush=True)

        # 6. Jump through the snapshot helper. USB may disappear immediately;
        # the separate ADB/Android checks must establish actual execution.
        send_word(mtk.port, 0xF00DD00D)
        send_word(mtk.port, 0x4001)
        print("BOOTSTRAP_HANDOFF_ATTEMPT", flush=True)
        try:
            send_word(mtk.port, 0x227001)
        except Exception as error:
            print(f"HANDOFF_USB_STATUS_UNOBSERVED: {error}", flush=True)
        print("RAM_HANDOFF_SENT: waiting for the separate USB recovery check", flush=True)
    finally:
        try:
            mtk.port.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtkclient-root", type=Path, required=True)
    parser.add_argument("--stage1", type=Path, required=True)
    parser.add_argument("--built-dir", type=Path, default=SOURCE / "build")
    parser.add_argument("--target-meid-sha256")
    parser.add_argument("--run", action="store_true",
                        help="perform the volatile USB BootROM handoff")
    args = parser.parse_args()
    stages = preflight(args)
    if args.run:
        handoff(args, stages)
    else:
        print("PREFLIGHT_ONLY: no USB or eMMC command was sent", flush=True)


if __name__ == "__main__":
    main()
