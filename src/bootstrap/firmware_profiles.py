"""Exact image profiles for the volatile Echo Plus 2 bootstrap.

Unknown firmware can be captured for diagnosis, but it cannot be patched by
guessing a nearby address. These profiles never authorize a storage write.
"""

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class FirmwareProfile:
    name: str
    fingerprint: str
    kernel_build_date: str
    sel_read_enforce: int
    preloader: tuple[int, str]
    lk: tuple[int, str]
    boot: tuple[int, str]
    ramdisk: tuple[int, str]
    adbd: tuple[int, str]
    adbd_words: tuple[tuple[int, str], ...]
    preloader_patches: tuple[tuple[int, str, str, str], ...]
    lk_handoff: int
    thumb_cave: int
    branch_halfword: int
    archive_address: int
    initrd_end: int
    ramdisk_tail: str


NS6575_8338N = FirmwareProfile(
    name="NS6575-8338N",
    fingerprint="Amazon/lidar/lidar:6.0/NS6575/8338N:user/amz-p,release-keys",
    kernel_build_date="2026-10-14",
    sel_read_enforce=0xffffff80082e57a8,
    preloader=(146484, "cd2d76ef7e9f7df301c21b1f0631b4e32dc4402b922c7cf3a590e2108135fae0"),
    lk=(1048576, "e1f541d1a793ca98d2d995f875d227998bd5ac6368e44d814f63a6515fff9d5c"),
    boot=(16777216, "3baf114f6382492e706795b229c4ff08f4fe62da6cf2172ba164830b518421b1"),
    ramdisk=(0x3ed7eb, "26f8cc663db7b0ad93776732dfde8dde14b5ed8e0a74d7eddd8e42bf370aa072"),
    adbd=(683932, "4d068fa301d85716b07623a5c112089454d70b866f29a140c3621da57d05e7ae"),
    adbd_words=((0x716, "2df05bfe"), (0x720, "2df044fe"), (0x68e, "22e057f0")),
    preloader_patches=(
        (0x2153d0, "2de9f34efff784ff64209a4c", "fff784ff", "00f000b8"),
        (0x20e290, "65fc2046fff7bef9012803d1", "fff7bef9", "00f006b8"),
        (0x20e5b4, "4ff45072fff7f0fd06f042fe", "fff7f0fd", "17f024fd"),
    ),
    lk_handoff=0x41e1be56, thumb_cave=0x41e24500, branch_halfword=0xbb53,
    archive_address=0x443ed7eb, initrd_end=0x443edfe1,
    ramdisk_tail="602332e0008e5f00",
)


# This September image was recovered from the owner's inactive slot and
# independently matched against Amazon's full NS65741/8149N OTA. Its LK and
# executable preloader bytes are the same as the tested 8338N boot chain.
NS65741_8149N = FirmwareProfile(
    name="NS65741-8149N",
    fingerprint="Amazon/lidar/lidar:6.0/NS65741/8149N:user/amz-p,release-keys",
    kernel_build_date="2026-09-28",
    sel_read_enforce=NS6575_8338N.sel_read_enforce,
    preloader=NS6575_8338N.preloader,
    lk=NS6575_8338N.lk,
    boot=(16777216, "4ac4ac7d9e843af04c5a1ccef46abe37e16676c22f007eaf8747880249fcf3d4"),
    ramdisk=(0x3ed2c4, "c37edb7f231bdb243194f65bcd883fe194c778dbbdda5f6ae27dd4c7f60a3d5f"),
    adbd=NS6575_8338N.adbd,
    adbd_words=NS6575_8338N.adbd_words,
    preloader_patches=NS6575_8338N.preloader_patches,
    lk_handoff=NS6575_8338N.lk_handoff,
    thumb_cave=NS6575_8338N.thumb_cave,
    branch_halfword=NS6575_8338N.branch_halfword,
    archive_address=0x443ed2c4, initrd_end=0x443edaba,
    ramdisk_tail="0ea4592a00745f00",
)


# These names identify the captured boot images. Either image may be selected
# from either physical slot if its active LK and preloader match exactly.
NS6536_2509N = FirmwareProfile(
    name="NS6536-2509N",
    fingerprint="Amazon/lidar/lidar:6.0/NS6536/2509N:user/amz-p,release-keys",
    kernel_build_date="2020-03-06",
    sel_read_enforce=0xffffff8008329ba8,
    preloader=(144772, "b82fe781286104fb8663e6a8ff8450d5d74481874cd584257fe823aebd598c73"),
    lk=(1048576, "e856ca3ea7719c5014023ad7a5667fe555928a9dc9a7eb9bf455664cf010934f"),
    boot=(16777216, "839651fa5faed537144b1b4161d0d1c99180631bdae74ad2a43af4638d75bd36"),
    ramdisk=(0x3f0102, "cbadcb0ba868563d90dcc40830cd2ce4245febf9f2f24aa5736c0b1e63c40b9b"),
    adbd=(696228, "0ab838482c7d7913156430d1bd4c4f655ad6664d351267d82714284c85c16b1c"),
    adbd_words=((0x716, "2df04bfe"), (0x720, "2df034fe"), (0x68e, "22e057f0")),
    preloader_patches=(
        (0x214fb0, "2de9f34efff784ff64209a4c", "fff784ff", "00f000b8"),
        (0x20e1d0, "b5fa3046fff7eaf9012803d1", "fff7eaf9", "00f006b8"),
        (0x20e46c, "4ff45072fff704fe0be03248", "fff704fe", "17f0c8fd"),
        (0x20e486, "4ff45072fff727fe06f0c9fc", "fff727fe", "17f0bbfd"),
    ),
    lk_handoff=0x41e1bf62, thumb_cave=0x41e2451c, branch_halfword=0xbadb,
    archive_address=0x443f0102, initrd_end=0x443f08f8,
    ramdisk_tail="acea454e00e65e00",
)


NS6541_2965N = FirmwareProfile(
    name="NS6541-2965N",
    fingerprint="Amazon/lidar/lidar:6.0/NS6541/2965N:user/amz-p,release-keys",
    kernel_build_date="2020-10-12",
    sel_read_enforce=0xffffff8008329ce8,
    preloader=NS6536_2509N.preloader,
    lk=(1048576, "16a27f53c871a6fd0a45bb841650b721791e675f5a95e760a56e9e8f641e992b"),
    boot=(16777216, "57875d42dec8939b106e581001898f47829cd56bb99596ddf71c1405b9e140d5"),
    ramdisk=(0x3f0aed, "f4b07e289b937c47e8bafa9552bd50dea258b87e86aa66ec4e30aad20534af46"),
    adbd=(696228, "4b07fe0a969df407225f051940322c27d9fbb05682b49f3fc5d044184a26fe6d"),
    adbd_words=((0x716, "2df04bfe"), (0x720, "2df034fe"), (0x68e, "22e057f0")),
    preloader_patches=NS6536_2509N.preloader_patches,
    lk_handoff=0x41e1bf62, thumb_cave=0x41e2452c, branch_halfword=0xbae3,
    archive_address=0x443f0aed, initrd_end=0x443f12e3,
    ramdisk_tail="ad28b7c700fe5e00",
)


# Keep stable kernel IDs for already installed apps; order the public registry
# by the compile date embedded in each captured kernel image.
PROFILES = tuple(sorted((NS6575_8338N, NS65741_8149N,
                         NS6536_2509N, NS6541_2965N),
                        key=lambda profile: profile.kernel_build_date))


def by_name(name: str) -> FirmwareProfile:
    if name == "NS6541-boot-57875d42":
        return NS6541_2965N  # Marker from an earlier offline build.
    if name in ("NS6536-boot-839651fa", "NS6541-boot-839651fa"):
        return NS6536_2509N  # Markers from earlier offline builds.
    for profile in PROFILES:
        if profile.name == name:
            return profile
    raise ValueError(f"unsupported Echo Plus 2 firmware profile: {name}")


def select_profile(preloader: bytes, lk: bytes, boot: bytes) -> FirmwareProfile:
    """Select by exact active image identities, independent of their slot."""
    identity = tuple((len(image), hashlib.sha256(image).hexdigest())
                     for image in (preloader, lk, boot))
    matches = [profile for profile in PROFILES
               if (profile.preloader, profile.lk, profile.boot) == identity]
    if len(matches) != 1:
        raise ValueError("active preloader, LK and boot images have no checked RAM profile")
    return matches[0]


def active_slot(misc: bytes) -> str:
    """Return the unique bootable slot from the checked older boot_ctrl record."""
    if len(misc) != 4096 or misc[0x360:0x365] != bytes.fromhex("0041424201"):
        raise ValueError("A/B slot record has unknown magic or version")
    a, b = misc[0x365:0x367]
    priorities = (a & 15, b & 15)
    bootable = tuple(priority > 0 and (value & 0x80 or (value >> 4) & 7)
                     for value, priority in zip((a, b), priorities))
    if priorities[0] == priorities[1]:
        raise ValueError("A/B slot priorities tie")
    winner = 0 if priorities[0] > priorities[1] else 1
    if not bootable[winner]:
        raise ValueError("selected A/B slot is not bootable")
    return "a" if winner == 0 else "b"
