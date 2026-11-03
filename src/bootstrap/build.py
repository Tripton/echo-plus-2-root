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


SOURCE = Path(__file__).resolve().parent
PINNED = {
    "preloader": (146484, "cd2d76ef7e9f7df301c21b1f0631b4e32dc4402b922c7cf3a590e2108135fae0"),
    "lk_a": (1048576, "e1f541d1a793ca98d2d995f875d227998bd5ac6368e44d814f63a6515fff9d5c"),
    "lk_b": (1048576, "e1f541d1a793ca98d2d995f875d227998bd5ac6368e44d814f63a6515fff9d5c"),
    "boot_a": (16777216, "3baf114f6382492e706795b229c4ff08f4fe62da6cf2172ba164830b518421b1"),
    "stage1": (1000, "0cec003fb8b594ed374270debc0aefb198d03d66d0f4ef3db5d5f1e706098296"),
}
OUTPUTS = {
    "init.elf": (7952, "566dc3cdda18538c39de2d5c53ab2bc13a9923f7b6595db9c8928b4a0e6c50fb"),
    "initramfs_overlay.cpio.gz": (2038, "1d1bb4544782f7bfb200f5c13230a85d92d22844f698b6faef6b3acd7e2bb6d1"),
    "preloader_snapshot.bin": (184, "5e2d0711bff088738fb00935c71dd3dfa80009305cf6b12bfc5fce6a63b401c9"),
    "lk_bridge.bin": (232, "5954b8fdb2e6e2083efa17124336026f407e5ad7ac7c150c0458038cc8b6e487"),
    "handoff_cave.bin": (128, "a35e334735dfa1b566b418e18ae3c513626068dd099ce2ee048a8e4ca1074392"),
    "fdt_initrd.bin": (3064, "51e443fc6e0b2bb11cbf96e0db86931c7505e4a46abe96ec47dc69c15ea7d905"),
    "preloader_patched.bin": (145716, "1fd3baa00bb9a951ca3f7e5ef3a6ec4ac6d4c46696c190840814d0c04a1561c1"),
}
PRELOADER_BASE = 0x201000
LK_BASE = 0x41E00000
ARCHIVE_ADDRESS = 0x443ED7EB
BOOT_IMAGE_ENTRY = 0x40080000
RAMDISK_SIZE = 0x3ED7EB
RAMDISK_HASH = "26f8cc663db7b0ad93776732dfde8dde14b5ed8e0a74d7eddd8e42bf370aa072"
ADBD_HASH = "4d068fa301d85716b07623a5c112089454d70b866f29a140c3621da57d05e7ae"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked(path: Path, name: str) -> bytes:
    data = path.read_bytes()
    expected_size, expected_hash = PINNED[name]
    if len(data) != expected_size or sha(data) != expected_hash:
        raise ValueError(f"{name}: size or SHA-256 differs from tested 8338N input")
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


def build_init(temp: Path, clang: str, ld: str) -> bytes:
    object_file = temp / "init.o"
    image_file = temp / "init.elf"
    run([clang, "-target", "aarch64-none-elf", "-Oz", "-ffreestanding",
         "-fno-builtin", "-fno-stack-protector", "-fno-asynchronous-unwind-tables",
         "-nostdlib", "-c", str(SOURCE / "init.c"), "-o", str(object_file)])
    run([ld, "-T", str(SOURCE / "init.ld"), "-z", "max-page-size=0x1000",
         "--strip-all", "-o", str(image_file), str(object_file)])
    return image_file.read_bytes()


def build_assembly(temp: Path, name: str, target: str, address: int,
                   clang: str, ld: str, objcopy: str) -> bytes:
    object_file = temp / f"{name}.o"
    image_file = temp / f"{name}.elf"
    binary_file = temp / f"{name}.bin"
    run([clang, "-target", target, "-c", str(SOURCE / f"{name}.S"),
         "-o", str(object_file)], cwd=temp)
    run([ld, f"-Ttext=0x{address:x}", f"--entry=0x{address:x}",
         "-o", str(image_file), str(object_file)])
    run([objcopy, "-O", "binary", str(image_file), str(binary_file)])
    return binary_file.read_bytes()


def check_output(data: bytes, name: str) -> bytes:
    expected_size, expected_hash = OUTPUTS[name]
    if len(data) != expected_size or sha(data) != expected_hash:
        raise ValueError(f"{name}: build differs from tested image")
    print(f"BUILD_OK {name} bytes={len(data)} sha256={sha(data)}")
    return data


def patch_preloader(source: bytes) -> bytes:
    # The 0x300-byte GFH wrapper is not executed from SRAM. Check its load
    # address and declared length before taking the exact tested code body.
    if (source[:8] != bytes.fromhex("4d4d4d0138000000") or
            struct.unpack_from("<I", source, 0x1C)[0] != 0x200D00 or
            struct.unpack_from("<I", source, 0x20)[0] != len(source)):
        raise ValueError("preloader GFH or load address changed")
    body = bytearray(source[0x300:])
    if len(body) != 145716 or body[:8] != bytes.fromhex("00000000030000ea"):
        raise ValueError("preloader entry differs")
    # Two checked call skips and one LK handoff hook. The replacement words
    # are only valid at these exact addresses on the pinned preloader.
    patches = (
        (0x2153D0, "2de9f34efff784ff64209a4c", "fff784ff", "00f000b8"),
        (0x20E290, "65fc2046fff7bef9012803d1", "fff7bef9", "00f006b8"),
        (0x20E5B4, "4ff45072fff7f0fd06f042fe", "fff7f0fd", "17f024fd"),
    )
    for address, context_hex, old_hex, new_hex in patches:
        offset = address - PRELOADER_BASE
        context = bytes.fromhex(context_hex)
        check_bytes(body, "preloader context", context, offset - 4)
        check_bytes(body, "preloader instruction", bytes.fromhex(old_hex), offset)
        body[offset:offset + 4] = bytes.fromhex(new_hex)
    return check_output(bytes(body), "preloader_patched.bin")


def check_lk(lk: bytes) -> None:
    def offset(address: int) -> int:
        return address - LK_BASE + 0x200
    check_bytes(lk, "LK entry", bytes.fromhex("00000fe1"), offset(0x41E00080))
    check_bytes(lk, "LK handoff", bytes.fromhex("daf8000030b10698"), offset(0x41E1BE56))
    check_bytes(lk, "LK Thumb cave", b"\xff" * 128, offset(0x41E24500))
    check_bytes(lk, "LK AArch64 cave", bytes(3072), offset(0x41E32000))
    if LK_BASE + len(lk) < 0x41E32000 + 3072:
        raise ValueError("LK image does not include the AArch64 cave")


def check_layout(payload: dict[str, bytes]) -> None:
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
    image = payload["fdt_initrd.bin"]
    archive = payload["initramfs_overlay.cpio.gz"]
    if (image[984:1024] != bytes(40) or image[1024:1024 + len(archive)] != archive or
            image.count(archive) != 1 or
            image.count(b"initrd=0x44000000,0x3edfe1 panic=1 ") != 1 or
            ARCHIVE_ADDRESS + len(archive) != 0x443EDFE1):
        raise ValueError("embedded archive or fixed FDT replacement changed")


def build(args: argparse.Namespace) -> None:
    # Read and pin every private input first. This refuses other board or
    # firmware revisions instead of silently applying offsets to them.
    preloader = checked(args.preloader, "preloader")
    lk_a = checked(args.lk_a, "lk_a")
    lk_b = checked(args.lk_b, "lk_b")
    boot_a = checked(args.boot_a, "boot_a")
    checked(args.stage1, "stage1")
    if lk_a != lk_b:
        raise ValueError("LK A and B differ")
    check_lk(lk_a)
    stock_ramdisk = boot_ramdisk(boot_a, "boot_a")
    if not stock_ramdisk.startswith(b"\x1f\x8b\x08"):
        raise ValueError("boot_a: gzip ramdisk missing")
    if len(stock_ramdisk) != RAMDISK_SIZE or sha(stock_ramdisk) != RAMDISK_HASH:
        raise ValueError("boot_a ramdisk differs from tested live image")
    stock_files = cpio_entries(gzip.decompress(stock_ramdisk))
    adbd = stock_files["sbin/adbd"]
    if len(adbd) != 683932 or sha(adbd) != ADBD_HASH:
        raise ValueError("recovery adbd differs from checked 8338N binary")
    for offset, word in ((0x716, "2df05bfe"), (0x720, "2df044fe"),
                         (0x68e, "22e057f0")):
        check_bytes(adbd, "recovery adbd", bytes.fromhex(word), offset)
    if len(stock_files) != 159:
        raise ValueError("unexpected stock initramfs file count")
    print("FIRMWARE_LAYOUT_OK pinned 8338N LK, boot image and recovery adbd")

    # Build in a temporary directory. No generated binary enters the public
    # source tree, and the requested output is populated only after all tests.
    payload: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory() as folder:
        temp = Path(folder)
        elf = check_output(build_init(temp, args.clang, args.ld), "init.elf")
        archive = gzip.compress(
            newc_entry("init", elf, 0o100755, 270) +
            newc_entry("sbin", b"", 0o040755, 271) +
            newc_entry("sbin/multi_init", b"../init", 0o120777, 272) +
            newc_entry("TRAILER!!!", b"", 0, 273), compresslevel=9, mtime=0)
        # zlib versions disagree about the GZIP OS byte. Use the portable
        # value so the pinned payload is identical on supported Python builds.
        if archive[:3] != b"\x1f\x8b\x08" or archive[4:8] != b"\x00" * 4:
            raise RuntimeError("unexpected GZIP header")
        archive = archive[:9] + b"\xff" + archive[10:]
        payload["init.elf"] = elf
        payload["initramfs_overlay.cpio.gz"] = check_output(archive, "initramfs_overlay.cpio.gz")
        after = cpio_entries(gzip.decompress(stock_ramdisk + archive))
        if after != {**stock_files, "init": elf, "sbin/multi_init": b"../init"}:
            raise ValueError("overlay changes another stock initramfs member")
        (temp / "initramfs_overlay.cpio.gz").write_bytes(archive)
        for name, target, address in (
            ("preloader_snapshot", "armv7a-none-eabi", 0x227000),
            ("lk_bridge", "armv7a-none-eabi", 0x226000),
            ("handoff_cave", "armv7a-none-eabi", 0x41E24500),
            ("fdt_initrd", "aarch64-none-elf", 0x41E32000),
        ):
            binary_name = name + ".bin"
            payload[binary_name] = check_output(
                build_assembly(temp, name, target, address,
                               args.clang, args.ld, args.objcopy), binary_name)
    payload["preloader_patched.bin"] = patch_preloader(preloader)
    check_layout(payload)
    print("OFFLINE_BOOTSTRAP_PREFLIGHT_OK: all checked artifacts match the tested research build")
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in payload.items():
        (args.out / name).write_bytes(data)
    print(f"OUTPUT_DIR {args.out.resolve()}")
    print("OFFLINE_ONLY: no USB access or live eMMC operation was performed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("preloader", "lk-a", "lk-b", "boot-a", "stage1"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--out", type=Path, default=SOURCE / "build")
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--ld", default=shutil.which("ld.lld") or "ld.lld")
    parser.add_argument("--objcopy", default=shutil.which("llvm-objcopy") or "llvm-objcopy")
    build(parser.parse_args())


if __name__ == "__main__":
    main()
