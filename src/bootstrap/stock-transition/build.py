#!/usr/bin/env python3
"""Offline build of the tested RAM-only stock-init transition components.

The two init scripts and policy are private inputs extracted from the
owner's own image. This does not contact a device or write a live partition.
"""

import argparse
import hashlib
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
INPUTS = {
    "policy": (363124, "516fbcec49d7030f189f5efddf336c0d20ec64ae9e3c64aa4fd518cfe8cf4a6b"),
    "stock_usb_rc": (29585, "1b79645cff7787553704d0b637bc27fc7d0f1cf986ecfc5e422c778f697182e7"),
    "generic_usb_rc": (5715, "477c933077c6be4b851e8664da88f0529157ddeda6eed6f48ced6b2b8315092e"),
}
OUTPUTS = {
    "switchroot.elf": (5208, "08a9575891d669e941ec3e9ae49add383268a1f724649acf840fee00b561c016"),
    "safe-usb.rc": (29573, "b471071305577c0fcade3b73072c0c87d28aacf9f78bee1e58bcdf9fbf26c2b9"),
    "preserve-usb.rc": (5726, "5c41a8b9ef664b0802ca7fbabe9f96b2eddff5c3e5845fd54db0ad9ff78750df"),
}
# The research policy loader included host-path-dependent DWARF sections.
# Its mapped ELF bytes are reproducible even when those debug sections differ.
# This digest covers every PT_LOAD segment (including ELF and program headers),
# its virtual address, flags and memory size. Only section-table metadata in
# the ELF header is normalized because the kernel loader does not use it.
POLICY_LOADER_RUNTIME_SHA256 = "19ed809d4d8bcdff05add13b5a3c9e50d525de520fa66a55958981a047c3c836"
TCP_ADB_ON = b"    setprop service.adb.tcp.port 5555\n"
TCP_ADB_OFF = b"    setprop service.adb.tcp.port -1\n"
USB_DISABLE_TRIGGER = b"on property:sys.usb.config=none && property:sys.usb.configfs=0\n"
USB_INERT_TRIGGER = b"on property:sys.usb.config=lidar_no_action && property:sys.usb.configfs=0\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(data: bytes, name: str, expected: dict[str, tuple[int, str]]) -> bytes:
    size, digest = expected[name]
    if len(data) != size or sha(data) != digest:
        raise ValueError(f"{name}: size or SHA-256 differs from tested 8338N bytes")
    print(f"CHECK_OK {name} bytes={size} sha256={digest}")
    return data


def replace_once(source: bytes, old: bytes, new: bytes, name: str) -> bytes:
    if source.count(old) != 1:
        raise ValueError(f"{name}: expected exactly one source span")
    output = source.replace(old, new, 1)
    if output.count(new) != 1 or output.replace(new, old, 1) != source:
        raise ValueError(f"{name}: replacement is not reversible")
    return output


def patch_mtp_usb(source: bytes) -> bytes:
    """Edit only two fields of the owner's verified stock init trigger.

    The trigger is taken from the private input file, not copied into this
    repository. The entire source file and final output have pinned hashes.
    """
    matches = list(re.finditer(rb"(?m)^on property:sys\.usb\.config=mtp\n(?:[ \t]+[^\n]*\n)+", source))
    if len(matches) != 1:
        raise ValueError("expected one stock MTP trigger")
    original = matches[0].group()
    if len(original.splitlines()) != 7:
        raise ValueError("stock MTP trigger layout changed")
    patched = replace_once(original, b"/idProduct 2008\n", b"/idProduct 201D\n", "MTP product ID")
    patched = replace_once(patched, b"/functions ${sys.usb.config}\n", b"/functions mtp,adb\n", "MTP ADB function")
    return replace_once(source, original, patched, "MTP USB trigger")


def compile_switchroot(clang: str, ld: str) -> bytes:
    with tempfile.TemporaryDirectory() as folder:
        object_file = Path(folder) / "switchroot.o"
        elf_file = Path(folder) / "switchroot.elf"
        subprocess.run([clang, "-target", "aarch64-none-elf", "-c",
                        str(ROOT / "switchroot.S"), "-o", str(object_file)], check=True)
        subprocess.run([ld, "-T", str(ROOT / "switchroot.ld"),
                        "-z", "max-page-size=0x1000", "--strip-all",
                        "-o", str(elf_file), str(object_file)], check=True)
        return elf_file.read_bytes()


def policy_runtime_sha256(image: bytes) -> str:
    if len(image) < 64 or image[:6] != b"\x7fELF\x02\x01":
        raise ValueError("policy loader is not a little-endian ELF64 image")
    elf_type, machine = struct.unpack_from("<HH", image, 16)
    if elf_type != 2 or machine != 183:  # ET_EXEC, AArch64
        raise ValueError("policy loader architecture or ELF type differs")
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", image, 54)
    if phentsize != 56 or phnum == 0 or phoff + phentsize * phnum > len(image):
        raise ValueError("policy loader program headers are invalid")
    digest = hashlib.sha256()
    load_count = 0
    for index in range(phnum):
        kind, flags, offset, vaddr, _, size, memsize, _ = struct.unpack_from(
            "<IIQQQQQQ", image, phoff + index * phentsize)
        if kind != 1:  # PT_LOAD
            continue
        if offset + size > len(image) or size > memsize:
            raise ValueError("policy loader has an invalid load segment")
        data = bytearray(image[offset:offset + size])
        if offset == 0:
            # e_shoff, e_shentsize, e_shnum and e_shstrndx only describe
            # non-runtime sections. Source-path DWARF changes these fields.
            data[40:48] = bytes(8)
            data[58:64] = bytes(6)
        digest.update(struct.pack("<IQQQ", flags, vaddr, size, memsize))
        digest.update(data)
        load_count += 1
    if load_count != 4:
        raise ValueError("policy loader PT_LOAD layout differs")
    return digest.hexdigest()


def compile_policy_loader(cc: str) -> bytes:
    with tempfile.TemporaryDirectory() as folder:
        elf_file = Path(folder) / "policy-loader.elf"
        subprocess.run([cc, "-static", "-O2", "-g", "-Wall", "-Wextra",
                        "-Werror", "-Wl,-z,noexecstack", "-o", str(elf_file),
                        str(ROOT / "policy_load.c")], check=True)
        image = elf_file.read_bytes()
    actual = policy_runtime_sha256(image)
    if actual != POLICY_LOADER_RUNTIME_SHA256:
        raise ValueError("policy loader mapped bytes differ from the tested ELF")
    print(f"CHECK_OK policy-loader.elf mapped_sha256={actual} full_sha256={sha(image)}")
    return image


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--stock-usb-rc", type=Path, required=True)
    parser.add_argument("--generic-usb-rc", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "build")
    parser.add_argument("--clang", default=shutil.which("clang") or "clang")
    parser.add_argument("--ld", default=shutil.which("ld.lld") or "ld.lld")
    parser.add_argument("--policy-cc", required=True,
                        help="Android NDK aarch64-linux-android23-clang")
    args = parser.parse_args()

    check(args.policy.read_bytes(), "policy", INPUTS)
    stock_rc = check(args.stock_usb_rc.read_bytes(), "stock_usb_rc", INPUTS)
    generic_rc = check(args.generic_usb_rc.read_bytes(), "generic_usb_rc", INPUTS)

    # Disable the stock network ADB trigger and keep the temporary recovery
    # USB ADB function through Android's ordinary MTP transition. Both edits
    # are bind-mounted copies in RAM; the stock files remain on read-only /system.
    safe = replace_once(stock_rc, TCP_ADB_ON, TCP_ADB_OFF, "stock TCP ADB")
    safe = patch_mtp_usb(safe)
    preserve = replace_once(generic_rc, USB_DISABLE_TRIGGER,
                            USB_INERT_TRIGGER, "generic USB disable trigger")
    output = {
        "policy-loader.elf": compile_policy_loader(args.policy_cc),
        "switchroot.elf": check(compile_switchroot(args.clang, args.ld),
                                 "switchroot.elf", OUTPUTS),
        "safe-usb.rc": check(safe, "safe-usb.rc", OUTPUTS),
        "preserve-usb.rc": check(preserve, "preserve-usb.rc", OUTPUTS),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in output.items():
        (args.out / name).write_bytes(data)
    print(f"OFFLINE_STOCK_TRANSITION_PREFLIGHT_OK output={args.out.resolve()}")
    print("OFFLINE_ONLY: no USB or live eMMC access")


if __name__ == "__main__":
    main()
