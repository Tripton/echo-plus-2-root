#!/usr/bin/env python3
"""Offline build of the tested RAM-only stock-init transition components.

The two init scripts and policy are private inputs extracted from the
owner's own image. This does not contact a device or write a live partition.
"""

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from firmware_profiles import NS65741_8149N, NS6575_8338N, by_name


ROOT = Path(__file__).resolve().parent
INPUTS = {
    "policy": (363124, "516fbcec49d7030f189f5efddf336c0d20ec64ae9e3c64aa4fd518cfe8cf4a6b"),
    "stock_usb_rc": (29585, "1b79645cff7787553704d0b637bc27fc7d0f1cf986ecfc5e422c778f697182e7"),
    "generic_usb_rc": (5715, "477c933077c6be4b851e8664da88f0529157ddeda6eed6f48ced6b2b8315092e"),
}
NS65741_8149N_INPUTS = {
    **INPUTS,
    "policy": (357607, "b3f0276427bd28167b21b45c952d4b0eb710ff9376999660b7a179a7b0beaaf2"),
}
OUTPUTS = {
    "safe-usb.rc": (29573, "b471071305577c0fcade3b73072c0c87d28aacf9f78bee1e58bcdf9fbf26c2b9"),
    "preserve-usb.rc": (5726, "5c41a8b9ef664b0802ca7fbabe9f96b2eddff5c3e5845fd54db0ad9ff78750df"),
}
SWITCHROOT_MAPPED_SIZE = 800
SWITCHROOT_MAPPED_SHA256 = "94363b82f551154eb3301c357e12d98acd6c0dbd5c32e436833ceddacb31c6fc"
# The research policy loader included host-path-dependent DWARF sections.
# Its mapped ELF bytes are reproducible even when those debug sections differ.
# This digest covers every PT_LOAD segment (including ELF and program headers),
# its virtual address, flags and memory size. Only section-table metadata in
# the ELF header is normalized because the kernel loader does not use it.
POLICY_LOADER_RUNTIME_SHA256 = "19ed809d4d8bcdff05add13b5a3c9e50d525de520fa66a55958981a047c3c836"
NS65741_8149N_POLICY_LOADER_RUNTIME_SHA256 = "fc7e06039c392e929117fbdc625765764cf7b812068e517f0d75b63c7545c1b8"
TCP_ADB_ON = b"    setprop service.adb.tcp.port 5555\n"
TCP_ADB_OFF = b"    setprop service.adb.tcp.port -1\n"
USB_DISABLE_TRIGGER = b"on property:sys.usb.config=none && property:sys.usb.configfs=0\n"
USB_INERT_TRIGGER = b"on property:sys.usb.config=lidar_no_action && property:sys.usb.configfs=0\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(data: bytes, name: str, expected: dict[str, tuple[int, str]]) -> bytes:
    size, digest = expected[name]
    if len(data) != size or sha(data) != digest:
        raise ValueError(f"{name}: size or SHA-256 differs from the selected image")
    print(f"CHECK_OK {name} bytes={size} sha256={digest}")
    return data


def check_captured(data: bytes, name: str) -> bytes:
    """Bound an unarchived system file before the image-specific edit."""
    if name == "policy":
        if not (200000 <= len(data) <= 1048576 and
                data.startswith(bytes.fromhex("8cff7cf9080000005345204c696e7578"))):
            raise ValueError("captured SELinux policy has an unknown header or size")
    elif (not 1000 <= len(data) <= 65536 or b"\0" in data or
          not data.isascii() or b"\r" in data):
        raise ValueError(f"captured {name} has an unknown text layout")
    print(f"CAPTURED_INPUT_OK {name} bytes={len(data)} sha256={sha(data)}")
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
    if source.count(b"service.adb.tcp.port") != 1:
        raise ValueError("stock USB script has an unknown network ADB layout")
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


def check_switchroot_elf(image: bytes) -> bytes:
    """Pin the executable bytes and load layout, not host ELF section metadata."""
    if (not 4096 <= len(image) <= 65536 or
            image[:16] != b"\x7fELF\x02\x01\x01" + bytes(9)):
        raise ValueError("switchroot is not the expected little-endian ELF64 image")
    (elf_type, machine, version, entry, phoff, _, flags, ehsize,
     phentsize, phnum, _, _, _) = struct.unpack_from("<HHIQQQIHHHHHH", image, 16)
    if (elf_type != 2 or machine != 183 or version != 1 or
            entry != 0x10000 or flags != 0 or ehsize != 64 or
            phentsize != 56 or phnum != 1 or phoff < 64 or
            phoff + phentsize > len(image)):
        raise ValueError("switchroot ELF header or entry differs")
    kind, permissions, offset, virtual, physical, size, memory_size, alignment = (
        struct.unpack_from("<IIQQQQQQ", image, phoff))
    if (kind != 1 or permissions != 5 or virtual != 0x10000 or
            physical != virtual or size != SWITCHROOT_MAPPED_SIZE or
            memory_size != size or alignment != 0x1000 or
            offset < phoff + phentsize or offset % alignment != virtual % alignment or
            offset + size > len(image)):
        raise ValueError("switchroot load segment differs")
    mapped = sha(image[offset:offset + size])
    if mapped != SWITCHROOT_MAPPED_SHA256:
        raise ValueError(f"switchroot executable bytes differ from the tested image: "
                         f"mapped_sha256={mapped} full_sha256={sha(image)}")
    print(f"CHECK_OK switchroot.elf mapped_sha256={mapped} full_sha256={sha(image)}")
    return image


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


def compile_policy_loader(cc: str, policy_size: int,
                          expected_runtime: str | None) -> bytes:
    with tempfile.TemporaryDirectory() as folder:
        elf_file = Path(folder) / "policy-loader.elf"
        subprocess.run([cc, f"-DPOLICY_SIZE={policy_size}", "-static", "-O2", "-g", "-Wall", "-Wextra",
                        "-Werror", "-Wl,-z,noexecstack", "-o", str(elf_file),
                        str(ROOT / "policy_load.c")], check=True)
        image = elf_file.read_bytes()
    actual = policy_runtime_sha256(image)
    if expected_runtime is not None and actual != expected_runtime:
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
    parser.add_argument("--profile", required=True,
                        help="exact firmware image profile from the RAM build")
    args = parser.parse_args()

    profile = by_name(args.profile)
    exact_inputs = (INPUTS if profile == NS6575_8338N else
                    NS65741_8149N_INPUTS if profile == NS65741_8149N else None)
    input_check = (lambda data, name: check(data, name, exact_inputs)) if exact_inputs else check_captured

    policy = input_check(args.policy.read_bytes(), "policy")
    stock_rc = input_check(args.stock_usb_rc.read_bytes(), "stock_usb_rc")
    generic_rc = input_check(args.generic_usb_rc.read_bytes(), "generic_usb_rc")

    # Disable the stock network ADB trigger and keep the temporary recovery
    # USB ADB function through Android's ordinary MTP transition. Both edits
    # are bind-mounted copies in RAM; the stock files remain on read-only /system.
    safe = replace_once(stock_rc, TCP_ADB_ON, TCP_ADB_OFF, "stock TCP ADB")
    safe = patch_mtp_usb(safe)
    preserve = replace_once(generic_rc, USB_DISABLE_TRIGGER,
                            USB_INERT_TRIGGER, "generic USB disable trigger")
    expected_runtime = (POLICY_LOADER_RUNTIME_SHA256 if profile == NS6575_8338N else
                        NS65741_8149N_POLICY_LOADER_RUNTIME_SHA256
                        if profile == NS65741_8149N else None)
    loader = compile_policy_loader(args.policy_cc, len(policy), expected_runtime)
    if expected_runtime is None and policy_runtime_sha256(
            compile_policy_loader(args.policy_cc, len(policy), None)) != policy_runtime_sha256(loader):
        raise ValueError("policy loader is not reproducible across two builds")
    output = {
        "policy-loader.elf": loader,
        "switchroot.elf": check_switchroot_elf(compile_switchroot(args.clang, args.ld)),
        "safe-usb.rc": check(safe, "safe-usb.rc", OUTPUTS) if exact_inputs else safe,
        "preserve-usb.rc": check(preserve, "preserve-usb.rc", OUTPUTS) if exact_inputs else preserve,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in output.items():
        (args.out / name).write_bytes(data)
    manifest = {
        "profile": profile.name,
        "inputs": {"policy": sha(policy), "stock_usb_rc": sha(stock_rc),
                   "generic_usb_rc": sha(generic_rc)},
        "outputs": {name: sha(data) for name, data in output.items()},
        "policy_loader_runtime": policy_runtime_sha256(loader),
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    print(f"OFFLINE_STOCK_TRANSITION_PREFLIGHT_OK output={args.out.resolve()}")
    print("OFFLINE_ONLY: no USB or live eMMC access")


if __name__ == "__main__":
    main()
