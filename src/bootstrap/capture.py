#!/usr/bin/env python3
"""Read Echo Plus 2 boot inputs from the owner's device.

Without --run this checks only local MTKClient files. With --run it uses the
known BootROM entry, uploads MTKClient's download agents into RAM, and reads
bounded eMMC USER ranges. It never programs, erases, or selects BOOT1/BOOT2.
The preloader is saved after two matching SRAM reads, even when its firmware is
unsupported. Later eMMC reads require the checked preloader and DA setup. The
output is private firmware material and belongs in the ignored local/device
directory or another private directory.
"""

import argparse
import hashlib
import json
import logging
import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path

from build import PINNED
from firmware_profiles import PROFILES, active_slot, select_profile


SECTOR = 512
WINDOW = 0x10000
USER_BYTES = 7818182656
SRAM_BASE = 0x200000
SRAM_END = 0x238000
PRELOADER_MAGIC = bytes.fromhex("4d4d4d0138000000")
LOADER_SHA256 = "aef234190ccb8145d2e3b8459741e9adb70f2caa8481aa216c1b25152afaca1f"
PAYLOAD_SHA256 = "7bf98fa19b32eab41cf26578fe5017b3e277efa22f49e134ed4192c4634c8ecf"
PINNED_MTKCLIENT_REVISION = "7cb40e727727dfe3faa065eefb29b16ed29bbdf1"
EMI_SHA256 = "5132f9585472038b15ecdb5c3158a5823ee8fceb709bd0d098e0eecd9f4f2d8d"
DA2_SHA256 = "3f64ded6c216ce8d79d9d41c5cce18ac54ecb100d44152beff1af75602359630"
PARTITIONS = {
    "lk_a": (6144, *PINNED["lk_a"]),
    "lk_b": (18432, *PINNED["lk_b"]),
    "boot_a": (84992, *PINNED["boot_a"]),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_file(path: Path, expected_size: int | None, expected_sha: str) -> bytes:
    data = path.read_bytes()
    if (expected_size is not None and len(data) != expected_size) or sha(data) != expected_sha:
        raise RuntimeError(f"local bytes differ: {path}")
    return data


def local_inputs(mtk_root: Path) -> tuple[Path, Path]:
    revision = subprocess.check_output(
        ["git", "-C", str(mtk_root), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.run(
        ["git", "-C", str(mtk_root), "diff", "--quiet", "HEAD"],
        check=False).returncode
    untracked = subprocess.check_output(
        ["git", "-C", str(mtk_root), "ls-files", "--others", "--exclude-standard",
         "--", "mtkclient"], text=True).strip()
    if revision != PINNED_MTKCLIENT_REVISION or dirty != 0 or untracked:
        raise RuntimeError("MTKClient source differs from the tested revision")
    loader = mtk_root / "mtkclient/Loader/MTK_DA_V5.bin"
    payload = mtk_root / "mtkclient/payloads/mt8167_payload.bin"
    checked_file(loader, None, LOADER_SHA256)
    checked_file(payload, None, PAYLOAD_SHA256)
    print("PREFLIGHT_CAPTURE_MTKCLIENT_OK", flush=True)
    return loader, payload


def read_sram(mtk, address: int, length: int) -> bytes:
    if address < SRAM_BASE or address + length > SRAM_END or length % 4:
        raise RuntimeError("SRAM read is outside the checked range")
    result = bytearray()
    for offset in range(0, length, 0x200):
        count = min(0x200, length - offset) // 4
        words = mtk.preloader.read32(address + offset, count)
        if not isinstance(words, (tuple, list)) or len(words) != count:
            raise RuntimeError(f"short SRAM read at 0x{address + offset:x}")
        result.extend(struct.pack(f"<{count}I", *words))
    return bytes(result)


def capture_preloader(mtk, output: Path) -> bytes:
    prefix = read_sram(mtk, SRAM_BASE, 0x10000)
    if prefix != read_sram(mtk, SRAM_BASE, 0x10000):
        raise RuntimeError("SRAM preloader header changed between reads")
    offset = prefix.find(PRELOADER_MAGIC)
    if offset < 0 or offset + 0x24 > len(prefix):
        raise RuntimeError("preloader header was not found in SRAM")
    length = struct.unpack_from("<I", prefix, offset + 0x20)[0]
    address = SRAM_BASE + offset
    padded_length = (length + 3) & ~3
    if offset % 4 or length < 0x1000 or address + padded_length > SRAM_END:
        raise RuntimeError(f"preloader header is outside SRAM: address=0x{address:x} bytes={length}")
    data = read_sram(mtk, address, padded_length)[:length]
    if data != read_sram(mtk, address, padded_length)[:length]:
        raise RuntimeError("SRAM preloader changed between reads")
    if (data[:8] != PRELOADER_MAGIC or
            struct.unpack_from("<I", data, 0x1c)[0] != address or
            struct.unpack_from("<I", data, 0x20)[0] != length):
        raise RuntimeError("SRAM preloader header changed during capture")
    path = output / "preloader-from-sram.bin"
    save_new_or_equal(path, data)
    print(f"CHECKPOINT_CAPTURE_PRELOADER_SAVED address=0x{address:x} "
          f"bytes={length} sha256={sha(data)}", flush=True)
    return data


def check_preloader_for_capture(data: bytes, diagnostic: bool) -> None:
    observed = (len(data), sha(data))
    if diagnostic:
        print(f"CHECKPOINT_DIAGNOSTIC_PRELOADER_SAVED bytes={observed[0]} sha256={observed[1]}", flush=True)
    else:
        if not any(profile.preloader == observed for profile in PROFILES):
            raise RuntimeError("Preloader saved, but this firmware has no checked RAM profile")
        print("CHECKPOINT_CAPTURE_PRELOADER_OK; active slot pending", flush=True)


def read_twice(mtk, offset: int, length: int) -> bytes:
    if (offset < 0 or length <= 0 or offset % SECTOR or length % SECTOR or
            offset + length > USER_BYTES or length > 16777216):
        raise RuntimeError("eMMC USER read is outside the checked bounds")
    copies = []
    for _ in range(2):
        data = mtk.daloader.da.readflash(offset, length, "", parttype="user", display=False)
        if not isinstance(data, (bytes, bytearray)) or len(data) != length:
            raise RuntimeError(f"short eMMC read at 0x{offset:x}")
        copies.append(bytes(data))
    if copies[0] != copies[1]:
        raise RuntimeError(f"eMMC reads differ at 0x{offset:x}")
    return copies[0]


def parse_gpt(window: bytes, window_offset: int, header_offset: int) -> tuple[dict, dict]:
    relative = header_offset - window_offset
    if relative < 0 or relative + SECTOR > len(window):
        raise RuntimeError("GPT header is outside its read window")
    header = window[relative:relative + SECTOR]
    if header[:8] != b"EFI PART":
        raise RuntimeError("GPT signature missing")
    revision, size, expected_crc = struct.unpack_from("<III", header, 8)
    if revision != 0x10000 or not 92 <= size <= SECTOR:
        raise RuntimeError("GPT header version or size differs")
    crc_input = bytearray(header[:size])
    crc_input[16:20] = bytes(4)
    if zlib.crc32(crc_input) & 0xffffffff != expected_crc:
        raise RuntimeError("GPT header CRC differs")
    current, backup, first_usable, last_usable = struct.unpack_from("<QQQQ", header, 24)
    entries_lba = struct.unpack_from("<Q", header, 72)[0]
    count, entry_size, entries_crc = struct.unpack_from("<III", header, 80)
    entries_offset = entries_lba * SECTOR
    entries_length = count * entry_size
    entries_relative = entries_offset - window_offset
    if (current * SECTOR != header_offset or backup >= USER_BYTES // SECTOR or
            not 2 <= first_usable <= last_usable < USER_BYTES // SECTOR or
            not 1 <= count <= 256 or entry_size not in (128, 256) or
            entries_length > WINDOW or entries_relative < 0 or
            entries_relative + entries_length > len(window)):
        raise RuntimeError("GPT bounds differ")
    entries = window[entries_relative:entries_relative + entries_length]
    if zlib.crc32(entries) & 0xffffffff != entries_crc:
        raise RuntimeError("GPT entry-array CRC differs")
    parts = {}
    occupied = []
    for index in range(count):
        entry = entries[index * entry_size:(index + 1) * entry_size]
        if entry[:16] == bytes(16):
            continue
        start, end = struct.unpack_from("<QQ", entry, 32)
        if not first_usable <= start <= end <= last_usable:
            raise RuntimeError("GPT partition lies outside usable range")
        name = entry[56:128].decode("utf-16le", "strict").split("\0", 1)[0]
        if not name or name in parts:
            raise RuntimeError("GPT partition name is empty or duplicated")
        parts[name] = (start, (end - start + 1) * SECTOR)
        occupied.append((start, end))
    occupied.sort()
    if any(left[1] >= right[0] for left, right in zip(occupied, occupied[1:])):
        raise RuntimeError("GPT partitions overlap")
    info = {"current_lba": current, "backup_lba": backup,
            "disk_guid": header[56:72].hex(), "entries_crc32": entries_crc}
    return info, parts


def check_gpt(primary: bytes, backup: bytes, *, require_layout: bool = True) -> dict:
    if len(primary) != WINDOW or len(backup) != WINDOW:
        raise RuntimeError("GPT read-window size differs")
    last_lba = USER_BYTES // SECTOR - 1
    first, first_parts = parse_gpt(primary, 0, SECTOR)
    last, last_parts = parse_gpt(backup, USER_BYTES - WINDOW, USER_BYTES - SECTOR)
    if (first["current_lba"] != 1 or first["backup_lba"] != last_lba or
            last["current_lba"] != last_lba or last["backup_lba"] != 1 or
            first["disk_guid"] != last["disk_guid"] or
            first["entries_crc32"] != last["entries_crc32"] or
            first_parts != last_parts):
        raise RuntimeError("GPT primary and backup disagree")
    if require_layout:
        for name, (expected_lba, size, _) in PARTITIONS.items():
            if first_parts.get(name) != (expected_lba, size):
                raise RuntimeError(f"GPT layout differs for {name}")
        if first_parts.get("misc") != (51200, 524288):
            raise RuntimeError("GPT misc partition differs")
    print("CHECKPOINT_CAPTURE_GPT_CRC_AND_LAYOUT_OK" if require_layout
          else "CHECKPOINT_DIAGNOSTIC_GPT_CRC_OK", flush=True)
    return {"user_bytes": USER_BYTES, "disk_guid": first["disk_guid"],
            "primary_sha256": sha(primary), "backup_sha256": sha(backup),
            "partitions": {name: {"lba": lba, "bytes": size}
                           for name, (lba, size) in first_parts.items()}}


def save_new_or_equal(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError(f"existing private capture differs: {path}")
        print(f"CAPTURE_FILE_VERIFIED {path.name} bytes={len(data)}", flush=True)
        return
    # This SMB share rejects hard links, even within one directory.
    # Create each capture exclusively, sync it, and check the bytes read back.
    # An interrupted write remains visible as a mismatching file on retry.
    created = False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if path.read_bytes() != data:
            raise RuntimeError(f"capture readback differs: {path}")
    except FileExistsError:
        if path.read_bytes() != data:
            raise RuntimeError(f"existing private capture differs: {path}")
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise
    print(f"CAPTURE_FILE_SAVED {path.name} bytes={len(data)}", flush=True)


def verify_captures(directory: Path) -> None:
    slot = active_slot((directory / "misc-window.bin").read_bytes())
    preloader = (directory / "preloader-from-sram.bin").read_bytes()
    lk = (directory / f"lk_{slot}.bin").read_bytes()
    boot = (directory / f"boot_{slot}-live.bin").read_bytes()
    profile = select_profile(preloader, lk, boot)
    primary = (directory / "gpt-primary-window.bin").read_bytes()
    backup = (directory / "gpt-backup-window.bin").read_bytes()
    check_gpt(primary, backup)
    print(f"PREFLIGHT_CAPTURE_OUTPUTS_OK: {profile.name} slot {slot.upper()}", flush=True)


def capture(args: argparse.Namespace, loader: Path, payload: Path) -> None:
    # MTKClient imports only after the local, read-only preflight. The live
    # path is intentionally linear so every transition has a checked result.
    sys.path.insert(0, str(args.mtkclient_root))
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.config.brom_config import DAmodes
    from mtkclient.config.mtk_config import MtkConfig

    config = MtkConfig(loglevel=logging.INFO)
    # The older Kamakiri control request is rejected by Linux usbfs. The
    # Kamakiri2 path completed a checked read-only capture on this unit in an
    # Arch Linux ARM guest without changing the pinned MTKClient source.
    config.ptype = "kamakiri2" if sys.platform.startswith("linux") else "kamakiri"
    config.payloadfile = str(payload)
    config.loader = str(loader)
    config.hwparam_path = str(args.output_dir)
    config.skipwdt = False
    mtk = Mtk(config=config, loglevel=logging.INFO)
    try:
        print("WAIT_FOR_BOOTROM: hold Action and reconnect power now", flush=True)
        if not mtk.preloader.init():
            raise RuntimeError("BootROM handshake failed")
        meid = mtk.config.meid
        if (mtk.config.hwcode != 0x8167 or not mtk.config.is_brom or
                not isinstance(meid, (bytes, bytearray, memoryview)) or len(meid) != 16):
            raise RuntimeError("connected BootROM identity differs")
        meid_hash = sha(bytes(meid))
        if args.target_meid_sha256 and meid_hash != args.target_meid_sha256:
            raise RuntimeError("connected BootROM is not the previously captured Echo")
        print("CHECKPOINT_CAPTURE_BROM_ID_OK", flush=True)
        print("RELEASE_ACTION_NOW: BootROM identified", flush=True)
        if any(mtk.config.target_config[name] for name in
               ("sbc", "daa", "memread", "memwrite", "cmdC8")):
            mtk = mtk.bypass_security()
            if mtk is None:
                raise RuntimeError("Kamakiri failed")
        status = mtk.preloader.get_target_config(display=False)
        if any(status.values()):
            raise RuntimeError("BootROM security flags remain enabled")
        mtk.config.target_config = status
        print("CAPTURE_READING_PRELOADER", flush=True)
        preloader = capture_preloader(mtk, args.output_dir)
        check_preloader_for_capture(preloader, args.diagnose)

        dc = mtk.daloader.daconfig
        entry = dc.setup()
        if (entry is None or entry.hw_code != 0x8167 or entry.hw_sub_code != 0x8a00 or
                len(entry.region) != 3 or dc.config.chipconfig.damode != DAmodes.XFLASH):
            raise RuntimeError("DA selection differs from the checked MT8167 entry")
        da1, da2 = entry.region[1:3]
        if (da1.m_start_addr != 0x200000 or da1.m_len != 160136 or
                da2.m_start_addr != 0x40000000 or da2.m_len != 350872 or
                da2.m_sig_len != 256):
            raise RuntimeError("DA region geometry differs")
        dc.extract_emi(preloader)
        if dc.emiver != 28 or dc.emi is None or sha(dc.emi) != EMI_SHA256:
            raise RuntimeError("preloader DRAM/EMI setup differs; only the preloader was saved")
        mtk.daloader.set_da()
        if not mtk.daloader.da.upload_da1():
            raise RuntimeError("DA1 did not synchronize")
        if mtk.daloader.da.get_connection_agent() != b"brom" or dc.da2 is None or \
                sha(dc.da2) != DA2_SHA256:
            raise RuntimeError("DA1 connection or patched DA2 differs")
        mtk.daloader.da.set_reset_key(0x68)
        mtk.daloader.da.set_checksum_level(0)
        if not mtk.daloader.da.send_emi(dc.emi):
            raise RuntimeError("DA1 rejected checked EMI")
        sram, dram = mtk.daloader.da.get_ram_info()
        if (sram is None or dram is None or sram.base_address != SRAM_BASE or
                sram.size != SRAM_END - SRAM_BASE or dram.base_address != 0x40000000 or
                not 0x4000000 <= dram.size <= 0x80000000 or
                da2.m_start_addr + len(dc.da2) > dram.base_address + dram.size):
            raise RuntimeError("DA1 memory geometry differs")
        if not mtk.daloader.da.boot_to(da2.m_start_addr, dc.da2):
            raise RuntimeError("DA2 did not synchronize")
        emmc = mtk.daloader.da.get_emmc_info(display=False)
        if (emmc is None or emmc.type != 1 or emmc.block_size != SECTOR or
                emmc.user_size != USER_BYTES):
            raise RuntimeError("eMMC USER geometry differs")
        storage = dc.storage
        storage.flashtype = "emmc"
        storage.emmc = emmc
        storage.set_flash_size()
        if storage.flashsize != USER_BYTES:
            raise RuntimeError("eMMC USER selection differs")
        print("CHECKPOINT_CAPTURE_DA2_READ_ONLY_OK", flush=True)

        print("CAPTURE_READING_PARTITION_TABLE", flush=True)
        primary = read_twice(mtk, 0, WINDOW)
        backup = read_twice(mtk, USER_BYTES - WINDOW, WINDOW)
        output = args.output_dir
        save_new_or_equal(output / "gpt-primary-window.bin", primary)
        save_new_or_equal(output / "gpt-backup-window.bin", backup)
        report = check_gpt(primary, backup, require_layout=not args.diagnose)
        report["meid_sha256"] = meid_hash
        if args.diagnose:
            report["preloader_sha256"] = sha(preloader)
        parts = report["partitions"]
        misc_part = parts.get("misc")
        if misc_part is None or not 4096 <= misc_part["bytes"] <= 1048576:
            raise RuntimeError("GPT misc partition is missing or unusually sized")
        misc = read_twice(mtk, misc_part["lba"] * SECTOR, 4096)
        save_new_or_equal(output / "misc-window.bin", misc)
        slot = None if args.diagnose else active_slot(misc)
        if slot is not None:
            print(f"CHECKPOINT_CAPTURE_ACTIVE_{slot.upper()}_RECORD_OK", flush=True)
        different_images = []
        names = (("lk_a", "lk_b", "boot_a", "boot_b") if args.diagnose else
                 (f"lk_{slot}", f"boot_{slot}"))
        for name in names:
            if args.diagnose:
                part = parts.get(name)
                if part is None or not 4096 <= part["bytes"] <= 16777216:
                    raise RuntimeError(f"GPT {name} partition is missing or unusually sized")
                lba, size = part["lba"], part["bytes"]
                expected_sha = PARTITIONS[name][2] if name in PARTITIONS else None
            else:
                lba = (117760 if name == "boot_b" else
                       18432 if name == "lk_b" else PARTITIONS[name][0])
                size = 16777216 if name.startswith("boot_") else 1048576
                expected_sha = None
                if parts.get(name) != {"lba": lba, "bytes": size}:
                    raise RuntimeError(f"GPT layout differs for {name}")
            print(f"CAPTURE_READING_{name.upper()} bytes={size} twice", flush=True)
            image = read_twice(mtk, lba * SECTOR, size)
            filename = f"{name}-live.bin" if name.startswith("boot_") else f"{name}.bin"
            save_new_or_equal(output / filename, image)
            if args.diagnose:
                print(f"DIAGNOSTIC_IMAGE_SAVED {name} bytes={size}", flush=True)
                if expected_sha is not None and sha(image) != expected_sha:
                    different_images.append(name)
            else:
                print(f"CHECKPOINT_CAPTURE_{name.upper()}_SAVED bytes={size}", flush=True)
        profile = None
        if not args.diagnose:
            profile = select_profile(preloader,
                                     (output / f"lk_{slot}.bin").read_bytes(),
                                     (output / f"boot_{slot}-live.bin").read_bytes())
        if args.diagnose:
            report["diagnostic_only"] = True
            report["images_different_from_tested_build"] = different_images
        else:
            report["firmware_profile"] = profile.name
        save_new_or_equal(output / "capture-report.json",
                          (json.dumps(report, indent=2) + "\n").encode())
        if args.diagnose:
            print(f"DIAGNOSTIC_DUMP_READY: private files saved under {output}; no RAM image built", flush=True)
        else:
            print(f"CAPTURE_READY: private files saved under {output}", flush=True)
    finally:
        try:
            mtk.port.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtkclient-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-meid-sha256")
    parser.add_argument("--diagnose", action="store_true",
                        help="read-only capture for other firmware with the checked DRAM setup")
    parser.add_argument("--verify-captures", action="store_true")
    parser.add_argument("--run", action="store_true", help="perform read-only live capture")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    output = args.output_dir.resolve()
    if output.is_relative_to(repo) and not output.is_relative_to(repo / "local" / "device"):
        raise RuntimeError("private output inside the repository must be under local/device")
    loader, payload = local_inputs(args.mtkclient_root)
    if args.verify_captures:
        if args.diagnose:
            raise RuntimeError("diagnostic captures cannot be used as tested boot inputs")
        verify_captures(args.output_dir)
    if not args.run:
        print("PREFLIGHT_ONLY: no USB or eMMC access", flush=True)
        return
    if args.target_meid_sha256 and (len(args.target_meid_sha256) != 64 or
            any(char not in "0123456789abcdef" for char in args.target_meid_sha256)):
        raise RuntimeError("--target-meid-sha256 must be 64 lowercase hex characters")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    capture(args, loader, payload)
    if not args.diagnose:
        verify_captures(args.output_dir)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"STOP_CAPTURE: {error}")
