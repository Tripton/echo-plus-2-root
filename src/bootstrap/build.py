#!/usr/bin/env python3
"""Build the tested one-time Echo Plus 2 SRAM payload, entirely offline.

This builder accepts firmware copied from the owner's own LIDAR device. It
does not import MTKClient, open USB or access a live eMMC. All image-specific
assumptions are checked before a binary is written to the output directory.
The resulting files feed the guarded one-time bootstrap used in the tested release.
"""

import argparse
import gzip
import hashlib
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from firmware_profiles import (NS6536_2509N, NS6541_2965N,
                               NS65741_8149N, NS6575_8338N,
                               FirmwareProfile, active_slot, select_profile)


SOURCE = Path(__file__).resolve().parent
PINNED = {
    "preloader": (146484, "cd2d76ef7e9f7df301c21b1f0631b4e32dc4402b922c7cf3a590e2108135fae0"),
    "lk_a": (1048576, "e1f541d1a793ca98d2d995f875d227998bd5ac6368e44d814f63a6515fff9d5c"),
    "lk_b": (1048576, "e1f541d1a793ca98d2d995f875d227998bd5ac6368e44d814f63a6515fff9d5c"),
    "boot_a": (16777216, "3baf114f6382492e706795b229c4ff08f4fe62da6cf2172ba164830b518421b1"),
    "stage1": (1000, "0cec003fb8b594ed374270debc0aefb198d03d66d0f4ef3db5d5f1e706098296"),
}
NS6575_8338N_SLOT_A_OUTPUTS = {
    "preloader_snapshot.bin": (184, "5e2d0711bff088738fb00935c71dd3dfa80009305cf6b12bfc5fce6a63b401c9"),
    "lk_bridge.bin": (232, "5954b8fdb2e6e2083efa17124336026f407e5ad7ac7c150c0458038cc8b6e487"),
    "handoff_cave.bin": (128, "a35e334735dfa1b566b418e18ae3c513626068dd099ce2ee048a8e4ca1074392"),
    "preloader_patched.bin": (145716, "1fd3baa00bb9a951ca3f7e5ef3a6ec4ac6d4c46696c190840814d0c04a1561c1"),
}
NS6541_2965N_SLOT_B_OUTPUTS = {
    "preloader_snapshot.bin": NS6575_8338N_SLOT_A_OUTPUTS["preloader_snapshot.bin"],
    "lk_bridge.bin": (244, "ac140e67c858d6ab496b4d1b99374bf40a2e68f818bca905012340fd3422efcc"),
    "handoff_cave.bin": (128, "4601f9cca2c7e15b5b73d4416159532c6c5e5dec3669458ef59bd995392e85c0"),
    "preloader_patched.bin": (144004, "49be3ad8968ecb37c2180c06e31238e8b726b0afe6caeece0058ae395749a297"),
}
NS6575_8338N_SLOT_B_OUTPUTS = {
    **NS6575_8338N_SLOT_A_OUTPUTS,
}
NS65741_8149N_SLOT_A_OUTPUTS = {
    **NS6575_8338N_SLOT_A_OUTPUTS,
}
NS65741_8149N_SLOT_B_OUTPUTS = {
    **NS6575_8338N_SLOT_B_OUTPUTS,
}
NS6536_2509N_SLOT_A_OUTPUTS = {
    **NS6541_2965N_SLOT_B_OUTPUTS,
    "lk_bridge.bin": (244, "0f6b75770a23d97f23258edf1ce60f8ff69af00ae02fbb57b3a8bbecb37af043"),
}
NS6536_2509N_SLOT_B_OUTPUTS = {
    **NS6541_2965N_SLOT_B_OUTPUTS,
    "lk_bridge.bin": NS6536_2509N_SLOT_A_OUTPUTS["lk_bridge.bin"],
}
NS6541_2965N_SLOT_A_OUTPUTS = {
    **NS6541_2965N_SLOT_B_OUTPUTS,
}
OUTPUTS_BY_PROFILE_SLOT = {
    (NS6575_8338N.name, "a"): NS6575_8338N_SLOT_A_OUTPUTS,
    (NS6575_8338N.name, "b"): NS6575_8338N_SLOT_B_OUTPUTS,
    (NS65741_8149N.name, "a"): NS65741_8149N_SLOT_A_OUTPUTS,
    (NS65741_8149N.name, "b"): NS65741_8149N_SLOT_B_OUTPUTS,
    (NS6536_2509N.name, "a"): NS6536_2509N_SLOT_A_OUTPUTS,
    (NS6536_2509N.name, "b"): NS6536_2509N_SLOT_B_OUTPUTS,
    (NS6541_2965N.name, "a"): NS6541_2965N_SLOT_A_OUTPUTS,
    (NS6541_2965N.name, "b"): NS6541_2965N_SLOT_B_OUTPUTS,
}
PRELOADER_BASE = 0x201000
LK_BASE = 0x41E00000
BOOT_IMAGE_ENTRY = 0x40080000


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked(path: Path, name: str, expected: tuple[int, str] | None = None) -> bytes:
    data = path.read_bytes()
    expected_size, expected_hash = expected or PINNED[name]
    if len(data) != expected_size or sha(data) != expected_hash:
        raise ValueError(f"{name}: size or SHA-256 differs from the selected firmware profile")
    print(f"INPUT_OK {name} bytes={len(data)} sha256={sha(data)}")
    return data


def check_bytes(data: bytes, name: str, expected: bytes, offset: int) -> None:
    if data[offset:offset + len(expected)] != expected:
        raise ValueError(f"{name}: guarded bytes differ at offset 0x{offset:x}")


def align(value: int, unit: int) -> int:
    return (value + unit - 1) // unit * unit


def boot_ramdisk(image: bytes, name: str) -> bytes:
    if image[:8] != b"ANDROID!":
        raise ValueError(f"{name}: Android boot magic missing")
    kernel_size, kernel_addr, ramdisk_size, _, second_size, _, _, page_size, dt_size, _ = struct.unpack_from("<10I", image, 8)
    if kernel_addr != BOOT_IMAGE_ENTRY or page_size != 2048 or second_size or dt_size:
        raise ValueError(f"{name}: unexpected boot-image header")
    ramdisk_start = page_size + align(kernel_size, page_size)
    if ramdisk_start + ramdisk_size > len(image):
        raise ValueError(f"{name}: ramdisk exceeds partition image")
    return image[ramdisk_start:ramdisk_start + ramdisk_size]


def cpio_entries(raw: bytes) -> dict[str, bytes]:
    """Read the stock newc archive and its appended overlay in extraction order."""
    files: dict[str, bytes] = {}
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset] == 0:
            offset += 1
        if offset == len(raw):
            break
        if offset + 110 > len(raw) or raw[offset:offset + 6] not in (b"070701", b"070702"):
            raise ValueError(f"invalid CPIO header at 0x{offset:x}")
        fields = [int(raw[offset + 6 + 8 * i:offset + 14 + 8 * i], 16)
                  for i in range(13)]
        data_size, name_size = fields[6], fields[11]
        name_start = offset + 110
        name_end = name_start + name_size
        if name_size < 1 or name_end > len(raw) or raw[name_end - 1] != 0:
            raise ValueError("invalid CPIO name")
        name = raw[name_start:name_end - 1].decode("utf-8")
        payload_start = align(name_end, 4)
        payload_end = payload_start + data_size
        if payload_end > len(raw):
            raise ValueError("CPIO payload exceeds archive")
        if name != "TRAILER!!!":
            files[name] = raw[payload_start:payload_end]
        offset = align(payload_end, 4)
    return files


def newc_entry(name: str, data: bytes, mode: int, inode: int) -> bytes:
    name_bytes = name.encode("ascii") + b"\0"
    fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_bytes), 0)
    header = b"070701" + b"".join(f"{field:08x}".encode("ascii") for field in fields)
    result = header + name_bytes
    result += b"\0" * (-len(result) % 4)
    result += data
    return result + b"\0" * (-len(result) % 4)


def run(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, check=True, cwd=cwd)


def build_init(temp: Path, clang: str, ld: str, source: Path = SOURCE) -> bytes:
    object_file = temp / "init.o"
    image_file = temp / "init.elf"
    run([clang, "-target", "aarch64-none-elf", "-Oz", "-ffreestanding",
         "-fno-builtin", "-fno-stack-protector", "-fno-asynchronous-unwind-tables",
         "-nostdlib", "-c", str(source / "init.c"), "-o", str(object_file)])
    run([ld, "-T", str(SOURCE / "init.ld"), "-z", "max-page-size=0x1000",
         "--strip-all", "-o", str(image_file), str(object_file)])
    return image_file.read_bytes()


def check_init_elf(data: bytes) -> None:
    """Check the one bounded AArch64 segment loaded by the initramfs."""
    if len(data) < 120 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("bootstrap init is not a little-endian ELF64 image")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    elf_type, machine, version, entry, phoff, _, flags, ehsize, phentsize, phnum, _, _, _ = header
    if (elf_type != 2 or machine != 183 or version != 1 or entry != 0x10000 or
            flags != 0 or ehsize != 64 or phentsize != 56 or phnum != 1 or
            phoff + phentsize > len(data)):
        raise ValueError("bootstrap init ELF header or entry changed")
    segment = struct.unpack_from("<IIQQQQQQ", data, phoff)
    kind, permissions, offset, virtual, physical, file_size, memory_size, alignment = segment
    if (kind != 1 or permissions != 5 or offset != 0x1000 or
            virtual != 0x10000 or physical != virtual or
            not 0 < file_size <= 0x2000 or memory_size != file_size or
            alignment != 0x1000 or offset + file_size > len(data)):
        raise ValueError("bootstrap init load segment changed or exceeds its bound")


def build_assembly(temp: Path, name: str, target: str, address: int,
                   clang: str, ld: str, objcopy: str, source: Path = SOURCE) -> bytes:
    object_file = temp / f"{name}.o"
    image_file = temp / f"{name}.elf"
    binary_file = temp / f"{name}.bin"
    run([clang, "-target", target, "-c", str(source / f"{name}.S"),
         "-o", str(object_file)], cwd=temp)
    run([ld, f"-Ttext=0x{address:x}", f"--entry=0x{address:x}",
         "-o", str(image_file), str(object_file)])
    run([objcopy, "-O", "binary", str(image_file), str(binary_file)])
    return binary_file.read_bytes()


def check_output(data: bytes, name: str, profile: FirmwareProfile = NS6575_8338N,
                 slot: str = "a") -> bytes:
    expected_size, expected_hash = OUTPUTS_BY_PROFILE_SLOT[profile.name, slot][name]
    if len(data) != expected_size or sha(data) != expected_hash:
        raise ValueError(f"{name}: build differs from checked {profile.name} image")
    print(f"BUILD_OK {name} bytes={len(data)} sha256={sha(data)}")
    return data


def patch_preloader(source: bytes, profile: FirmwareProfile = NS6575_8338N,
                    slot: str = "a") -> bytes:
    # The 0x300-byte GFH wrapper is not executed from SRAM. Check its load
    # address and declared length before taking the exact tested code body.
    if (source[:8] != bytes.fromhex("4d4d4d0138000000") or
            struct.unpack_from("<I", source, 0x1C)[0] != 0x200D00 or
            struct.unpack_from("<I", source, 0x20)[0] != len(source)):
        raise ValueError("preloader GFH or load address changed")
    body = bytearray(source[0x300:])
    if len(body) != profile.preloader[0] - 0x300 or body[:8] != bytes.fromhex("00000000030000ea"):
        raise ValueError("preloader entry differs")
    # Two checked call skips and one LK handoff hook. The replacement words
    # are only valid at these exact addresses on the pinned preloader.
    for address, context_hex, old_hex, new_hex in profile.preloader_patches:
        offset = address - PRELOADER_BASE
        context = bytes.fromhex(context_hex)
        check_bytes(body, "preloader context", context, offset - 4)
        check_bytes(body, "preloader instruction", bytes.fromhex(old_hex), offset)
        body[offset:offset + 4] = bytes.fromhex(new_hex)
    return check_output(bytes(body), "preloader_patched.bin", profile, slot)


def check_lk(lk: bytes, profile: FirmwareProfile = NS6575_8338N) -> None:
    def offset(address: int) -> int:
        return address - LK_BASE + 0x200
    check_bytes(lk, "LK entry", bytes.fromhex("00000fe1"), offset(0x41E00080))
    check_bytes(lk, "LK handoff", bytes.fromhex("daf8000030b10698"), offset(profile.lk_handoff))
    check_bytes(lk, "LK Thumb cave", b"\xff" * 128, offset(profile.thumb_cave))
    check_bytes(lk, "LK AArch64 cave", bytes(3072), offset(0x41E32000))
    if LK_BASE + len(lk) < 0x41E32000 + 3072:
        raise ValueError("LK image does not include the AArch64 cave")


def check_layout(payload: dict[str, bytes], profile: FirmwareProfile = NS6575_8338N,
                 slot: str = "a") -> None:
    image = payload["fdt_initrd.bin"]
    archive = payload["initramfs_overlay.cpio.gz"]
    if len(image) > 3072 or not 0 < len(archive) <= 2048:
        raise ValueError("FDT shim or compressed initramfs exceeds the 3072-byte LK cave")
    regions = (
        (0x201000, payload["preloader_patched.bin"]),
        (0x226000, payload["lk_bridge.bin"]),
        (0x227000, payload["preloader_snapshot.bin"]),
        (0x228000, payload["fdt_initrd.bin"] + bytes(3072 - len(payload["fdt_initrd.bin"]))),
        (0x229000, payload["handoff_cave.bin"]),
    )
    for index, (address, data) in enumerate(regions):
        padded_end = address + align(len(data), 512)
        if padded_end > 0x238000 or (index + 1 < len(regions) and
                                      padded_end > regions[index + 1][0]):
            raise ValueError(f"SRAM staging overlap at 0x{address:x}")
    end = profile.archive_address + len(archive) - 0x44000000
    if ((profile == NS6575_8338N and slot == "a" and image[984:1024] != bytes(40)) or
            image[1024:1024 + len(archive)] != archive or
            image.count(archive) != 1 or
            image.count(f"initrd=0x44000000,0x{end:x} panic=1 ".encode()) != 1):
        raise ValueError("embedded archive or FDT replacement changed")


def replace_once(text: str, old: str, new: str, expected: int = 1) -> str:
    if text.count(old) != expected:
        raise ValueError(f"bootstrap source changed around {old!r}")
    return text.replace(old, new)


def variant_sources(temp: Path, profile: FirmwareProfile, slot: str,
                    archive_length: int) -> Path:
    """Generate an isolated image/slot variant without changing tested source."""
    if profile == NS6575_8338N and slot == "a" and archive_length == 2038:
        return SOURCE
    source = temp / "variant_sources"
    source.mkdir(exist_ok=True)
    init = (SOURCE / "init.c").read_text()
    if profile in (NS6536_2509N, NS6541_2965N):
        init = replace_once(init, "0xfe5bf02d", "0xfe4bf02d")
        init = replace_once(init, "0xfe44f02d", "0xfe34f02d")
    if slot == "b":
        init = replace_once(init, "/dev/mmcblk0p13", "/dev/mmcblk0p14", 2)
        init = replace_once(init, "(179 << 8) | 13", "(179 << 8) | 14")
    (source / "init.c").write_text(init)

    bridge = (SOURCE / "lk_bridge.S").read_text()
    if profile in (NS6536_2509N, NS6541_2965N):
        for old, new, count in (
            ("0x41e1be56", "0x41e1bf62", 2),
            ("0x41e24500", f"0x{profile.thumb_cave:x}", 3),
            ("=0xbb53", f"=0x{profile.branch_halfword:x}", 1),
        ):
            bridge = replace_once(bridge, old, new, count)
        bridge = replace_once(
            bridge,
            "    ldr lr, =0x20e5b9\n    ldr pc, =0x20e199",
            "    /* Two checked preloader calls converge here. Return to the one that called us. */\n"
            "    push {r0}\n"
            "    ldr r0, =0x20e471\n"
            "    cmp lr, r0\n"
            "    pop {r0}\n"
            "    bne stock_atf\n"
            "    ldr pc, =0x20e079\n"
            "stock_atf:\n"
            "    ldr pc, =0x20e0d9",
        )
    (source / "lk_bridge.S").write_text(bridge)

    cave = (SOURCE / "handoff_cave.S").read_text()
    if profile in (NS6536_2509N, NS6541_2965N):
        cave = replace_once(cave, "0x41e1be56", "0x41e1bf62")
        cave = replace_once(cave, "0x41e1be5b", "0x41e1bf67", 2)
    (source / "handoff_cave.S").write_text(cave)
    (source / "preloader_snapshot.S").write_bytes((SOURCE / "preloader_snapshot.S").read_bytes())

    fdt = (SOURCE / "fdt_initrd.S").read_text()
    if profile != NS6575_8338N or archive_length != 2038:
        address = profile.archive_address
        end = profile.archive_address + archive_length - 0x44000000
        fdt = replace_once(fdt, "#0x443e", f"#0x{address >> 16:04x}", 2)
        fdt = replace_once(fdt, "#0xd7eb", f"#0x{address & 0xffff:04x}", 2)
        fdt = replace_once(fdt, "#2038", f"#{archive_length}", 2)
        fdt = replace_once(fdt, "0x3edfe1", f"0x{end:x}")
    if profile != NS6575_8338N or slot == "b":
        tail = profile.archive_address - 8
        tail_word = int.from_bytes(bytes.fromhex(profile.ramdisk_tail), "little")
        fdt = replace_once(
            fdt,
            "    movz x20, #0x41e3, lsl #16\n    movk x20, #0x2400",
            "    /* Refuse a changed boot image before touching its ramdisk. */\n"
            f"    movz x21, #0x{tail >> 16:04x}, lsl #16\n"
            f"    movk x21, #0x{tail & 0xffff:04x}\n"
            "    ldr x16, [x21]\n"
            "    ldr x17, ramdisk_tail\n"
            "    cmp x16, x17\n"
            "    b.ne forward\n"
            "    movz x20, #0x41e3, lsl #16\n"
            "    movk x20, #0x2400",
        )
        end = profile.archive_address + archive_length - 0x44000000
        replacement = f"replacement:\n    .ascii \"initrd=0x44000000,0x{end:x} panic=1 \""
        fdt = replace_once(
            fdt, replacement,
            replacement + "\n    .balign 8\nramdisk_tail:\n"
            f"    .quad 0x{tail_word:016x}",
        )
    (source / "fdt_initrd.S").write_text(fdt)
    return source


def build(args: argparse.Namespace) -> None:
    # Read and pin every private input first. This refuses other board or
    # firmware revisions instead of silently applying offsets to them.
    if args.misc is None:
        raise ValueError("checked A/B slot record is required to choose the RAM profile")
    slot = active_slot(args.misc.read_bytes())
    lk_path = args.lk_a if slot == "a" else args.lk_b
    boot_path = args.boot_a if slot == "a" else args.boot_b
    if lk_path is None or boot_path is None:
        raise ValueError(f"active slot {slot.upper()} needs its LK and boot images")
    profile = select_profile(args.preloader.read_bytes(), lk_path.read_bytes(),
                             boot_path.read_bytes())
    preloader = checked(args.preloader, "preloader", profile.preloader)
    lk = checked(lk_path, f"lk_{slot}", profile.lk)
    boot = checked(boot_path, f"boot_{slot}", profile.boot)
    checked(args.stage1, "stage1")
    check_lk(lk, profile)
    stock_ramdisk = boot_ramdisk(boot, f"boot_{slot}")
    if not stock_ramdisk.startswith(b"\x1f\x8b\x08"):
        raise ValueError("boot image: gzip ramdisk missing")
    if (len(stock_ramdisk), sha(stock_ramdisk)) != profile.ramdisk:
        raise ValueError("boot ramdisk differs from checked image")
    stock_files = cpio_entries(gzip.decompress(stock_ramdisk))
    adbd = stock_files["sbin/adbd"]
    if (len(adbd), sha(adbd)) != profile.adbd:
        raise ValueError("recovery adbd differs from checked image")
    for offset, word in profile.adbd_words:
        check_bytes(adbd, "recovery adbd", bytes.fromhex(word), offset)
    if len(stock_files) != 159:
        raise ValueError("unexpected stock initramfs file count")
    print(f"FIRMWARE_LAYOUT_OK {profile.name} slot {slot.upper()}")

    # Build in a temporary directory. No generated binary enters the public
    # source tree, and the requested output is populated only after all tests.
    payload: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory() as folder:
        temp = Path(folder)
        source = variant_sources(temp, profile, slot, 2038)
        elf = build_init(temp, args.clang, args.ld, source)
        check_init_elf(elf)
        print(f"BUILD_LAYOUT_OK init.elf bytes={len(elf)} sha256={sha(elf)}")
        archive = gzip.compress(
            newc_entry("init", elf, 0o100755, 270) +
            newc_entry("sbin", b"", 0o040755, 271) +
            newc_entry("sbin/multi_init", b"../init", 0o120777, 272) +
            newc_entry("TRAILER!!!", b"", 0, 273), compresslevel=9, mtime=0)
        # zlib versions disagree about the GZIP OS byte. Use the portable
        # value so this header is stable across supported Python builds.
        if archive[:3] != b"\x1f\x8b\x08" or archive[4:8] != b"\x00" * 4:
            raise RuntimeError("unexpected GZIP header")
        archive = archive[:9] + b"\xff" + archive[10:]
        if len(archive) > 2048:
            raise ValueError("compressed initramfs exceeds the 2048-byte FDT payload space")
        payload["init.elf"] = elf
        payload["initramfs_overlay.cpio.gz"] = archive
        print(f"BUILD_LAYOUT_OK initramfs_overlay.cpio.gz bytes={len(archive)} sha256={sha(archive)}")
        after = cpio_entries(gzip.decompress(stock_ramdisk + archive))
        if after != {**stock_files, "init": elf, "sbin/multi_init": b"../init"}:
            raise ValueError("overlay changes another stock initramfs member")
        (temp / "initramfs_overlay.cpio.gz").write_bytes(archive)
        source = variant_sources(temp, profile, slot, len(archive))
        for name, target, address in (
            ("preloader_snapshot", "armv7a-none-eabi", 0x227000),
            ("lk_bridge", "armv7a-none-eabi", 0x226000),
            ("handoff_cave", "armv7a-none-eabi", profile.thumb_cave),
            ("fdt_initrd", "aarch64-none-elf", 0x41E32000),
        ):
            binary_name = name + ".bin"
            binary = build_assembly(temp, name, target, address,
                                    args.clang, args.ld, args.objcopy, source)
            if name == "fdt_initrd":
                payload[binary_name] = binary
                print(f"BUILD_LAYOUT_OK {binary_name} bytes={len(binary)} sha256={sha(binary)}")
            else:
                payload[binary_name] = check_output(binary, binary_name, profile, slot)
    payload["preloader_patched.bin"] = patch_preloader(preloader, profile, slot)
    check_layout(payload, profile, slot)
    print(f"OFFLINE_BOOTSTRAP_PREFLIGHT_OK: checked {profile.name} slot {slot.upper()} RAM image")
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in payload.items():
        (args.out / name).write_bytes(data)
    (args.out / "firmware-profile.txt").write_text(f"{profile.name} {slot}\n")
    print(f"OUTPUT_DIR {args.out.resolve()}")
    print("OFFLINE_ONLY: no USB access or live eMMC operation was performed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("preloader", "stage1"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--lk-a", type=Path)
    parser.add_argument("--lk-b", type=Path)
    parser.add_argument("--boot-a", type=Path)
    parser.add_argument("--boot-b", type=Path)
    parser.add_argument("--misc", type=Path)
    parser.add_argument("--out", type=Path, default=SOURCE / "build")
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--ld", default=shutil.which("ld.lld") or "ld.lld")
    parser.add_argument("--objcopy", default=shutil.which("llvm-objcopy") or "llvm-objcopy")
    build(parser.parse_args())


if __name__ == "__main__":
    main()
