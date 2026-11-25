/* Volatile PID 1 for the one-time bootstrap.
 *
 * The kernel extracts this second CPIO archive after the stock initramfs. The
 * new /init runs before Android and exposes an ADB and serial recovery window.
 * It mounts the selected system image read-only with noload; this code does
 * not issue an eMMC program or erase operation. The host later loads the stock
 * policy in RAM and hands control back to stock init.
 */
typedef long s64;

#define AT_FDCWD (-100L)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_NONBLOCK 2048
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define MS_RDONLY 1
#define MS_BIND 4096

static inline s64 call6(s64 number, s64 a0, s64 a1, s64 a2,
                        s64 a3, s64 a4, s64 a5) {
    register s64 x0 __asm__("x0") = a0;
    register s64 x1 __asm__("x1") = a1;
    register s64 x2 __asm__("x2") = a2;
    register s64 x3 __asm__("x3") = a3;
    register s64 x4 __asm__("x4") = a4;
    register s64 x5 __asm__("x5") = a5;
    register s64 x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                     "r"(x4), "r"(x5), "r"(x8) : "memory");
    return x0;
}

static void pause_short(void) {
    const s64 delay[2] = {0, 100000000};
    call6(101, (s64)delay, 0, 0, 0, 0, 0);
}

static void fatal(void) {
    call6(93, 1, 0, 0, 0, 0, 0);
    for (;;) {}
}

static s64 length(const char *text) {
    s64 n = 0;
    while (text[n]) n++;
    return n;
}

static s64 open_file(const char *path, s64 flags) {
    return call6(56, AT_FDCWD, (s64)path, flags, 0, 0, 0);
}

static int write_file(const char *path, const char *value) {
    s64 fd = open_file(path, O_WRONLY);
    if (fd < 0) return -1;
    s64 size = length(value);
    s64 written = call6(64, fd, (s64)value, size, 0, 0, 0);
    call6(57, fd, 0, 0, 0, 0, 0);
    return written == size ? 0 : -1;
}

static void say(s64 fd, const char *message) {
    call6(64, fd, (s64)message, length(message), 0, 0, 0);
}

static int make_chr(const char *path, s64 major, s64 minor) {
    return call6(33, AT_FDCWD, (s64)path, S_IFCHR | 0666,
                 (major << 8) | minor, 0, 0) < 0 ? -1 : 0;
}

static void patch_ram_adbd(void) {
    s64 fd = open_file("/sbin/adbd", O_RDWR);
    if (fd < 0) fatal();
    /* This base source uses the 8338N ramdisk adbd words. The offline builder
     * generates other exact-image variants after checking their full hashes.
     * The final site skips the PR_CAPBSET_DROP loop. */
    const s64 offsets[3] = {0x716, 0x720, 0x68e};
    const unsigned int expected[3] = {0xfe5bf02d, 0xfe44f02d, 0xf057e022};
    const unsigned int replacement[3] = {0xbf00bf00, 0xbf00bf00, 0xf057e03f};
    const int patch_count = 3;
    for (int i = 0; i < patch_count; i++) {
        unsigned int word = 0;
        if (call6(67, fd, (s64)&word, 4, offsets[i], 0, 0) != 4 ||
            word != expected[i]) fatal();
        word = replacement[i];
        if (call6(68, fd, (s64)&word, 4, offsets[i], 0, 0) != 4) fatal();
    }
    call6(57, fd, 0, 0, 0, 0, 0);
}

static void start_adbd(void) {
    s64 child = call6(220, 17, 0, 0, 0, 0, 0); /* clone(SIGCHLD) */
    if (child != 0) return;
    char *const args[] = {(char *)"/sbin/adbd",
                          (char *)"--device_banner=recovery", 0};
    char *const env[] = {(char *)"PATH=/system/bin:/system/xbin",
                         (char *)"ANDROID_ROOT=/system",
                         (char *)"ANDROID_DATA=/data", 0};
    call6(221, (s64)"/sbin/adbd", (s64)args, (s64)env, 0, 0, 0);
    call6(93, 127, 0, 0, 0, 0, 0);
    for (;;) {}
}

void _start(void) {
    /* 1. Create the minimal mounts and device nodes needed by recovery adbd. */
    call6(166, 0, 0, 0, 0, 0, 0); /* umask(0), /dev/null must be 0666 */
    call6(34, AT_FDCWD, (s64)"/dev", 0755, 0, 0, 0);
    call6(34, AT_FDCWD, (s64)"/proc", 0755, 0, 0, 0);
    call6(34, AT_FDCWD, (s64)"/sys", 0755, 0, 0, 0);
    if (call6(40, (s64)"tmpfs", (s64)"/dev", (s64)"tmpfs", 2,
              (s64)"mode=0755", 0) < 0) fatal();
    if (call6(40, (s64)"proc", (s64)"/proc", (s64)"proc", 0, 0, 0) < 0)
        fatal();
    if (call6(40, (s64)"sysfs", (s64)"/sys", (s64)"sysfs", 0, 0, 0) < 0)
        fatal();

    if (make_chr("/dev/null", 1, 3) ||
        make_chr("/dev/zero", 1, 5) ||
        make_chr("/dev/random", 1, 8) ||
        make_chr("/dev/urandom", 1, 9) ||
        make_chr("/dev/tty", 5, 0) ||
        make_chr("/dev/console", 5, 1) ||
        make_chr("/dev/ptmx", 5, 2))
        fatal();
    call6(34, AT_FDCWD, (s64)"/dev/pts", 0755, 0, 0, 0);
    call6(40, (s64)"devpts", (s64)"/dev/pts", (s64)"devpts", 0,
          (s64)"mode=0620,ptmxmode=0666", 0);

    /* 2. Use stock userspace tools from system_a, mounted read-only. */
    /* GPT entry 13 is system_a; /proc/partitions reports 179:13. */
    call6(34, AT_FDCWD, (s64)"/system_root", 0755, 0, 0, 0);
    if (call6(33, AT_FDCWD, (s64)"/dev/mmcblk0p13",
              S_IFBLK | 0600, (179 << 8) | 13, 0, 0) < 0 ||
        call6(40, (s64)"/dev/mmcblk0p13", (s64)"/system_root",
              (s64)"ext4", MS_RDONLY, (s64)"noload", 0) < 0) {
        fatal();
    }
    if (call6(40, (s64)"/system_root/system", (s64)"/system",
              0, MS_BIND, 0, 0) < 0) {
        fatal();
    }
    s64 shell = open_file("/system/bin/sh", O_RDONLY);
    if (shell < 0) fatal();
    call6(57, shell, 0, 0, 0, 0, 0);
    patch_ram_adbd();

    /* 3. Configure the USB gadget and wait briefly for FunctionFS ADB. */
    int tries;
    for (tries = 0; tries < 50; tries++) {
        if (write_file("/sys/class/android_usb/android0/enable", "0") == 0)
            break;
        pause_short();
    }
    if (tries == 50) fatal();
    if (write_file("/sys/class/android_usb/android0/iSerial", " ") ||
        write_file("/sys/class/android_usb/android0/idVendor", "0e8d") ||
        write_file("/sys/class/android_usb/android0/idProduct", "2007") ||
        write_file("/sys/class/android_usb/android0/f_acm/instances", "1") ||
        write_file("/sys/class/android_usb/android0/bDeviceClass", "02"))
        fatal();
    call6(34, AT_FDCWD, (s64)"/dev/usb-ffs", 0777, 0, 0, 0);
    call6(34, AT_FDCWD, (s64)"/dev/usb-ffs/adb", 0777, 0, 0, 0);
    if (call6(40, (s64)"adb", (s64)"/dev/usb-ffs/adb",
              (s64)"functionfs", 0, (s64)"uid=2000,gid=2000", 0) < 0)
        fatal();
    if (write_file("/sys/class/android_usb/android0/f_ffs/aliases", "adb"))
        fatal();
    start_adbd();
    int ffs_ready = 0;
    for (tries = 0; tries < 50; tries++) {
        if (call6(48, AT_FDCWD, (s64)"/dev/usb-ffs/adb/ep1",
                  0, 0, 0, 0) == 0) {
            ffs_ready = 1;
            break;
        }
        pause_short();
    }
    if (write_file("/sys/class/android_usb/android0/functions",
                   ffs_ready ? "acm,adb" : "acm")) fatal();
    write_file("/sys/devices/platform/mt_usb/cmode", "1");
    if (write_file("/sys/class/android_usb/android0/enable", "1")) fatal();

    /* 4. Keep a serial shell as a fallback if ADB did not enumerate. */
    s64 serial = -1;
    for (tries = 0; tries < 100; tries++) {
        if (call6(33, AT_FDCWD, (s64)"/dev/ttyGS0", S_IFCHR | 0600,
                  (246 << 8), 0, 0) == 0 || tries > 10) {
            serial = open_file("/dev/ttyGS0", O_RDWR | O_NONBLOCK);
            if (serial >= 0) break;
        }
        pause_short();
    }
    if (serial < 0) fatal();
    say(serial, ffs_ready ? "ADB_FFS_READY\r\n" : "ADB_FFS_TIMEOUT\r\n");

    call6(25, serial, 4, 0, 0, 0, 0); /* clear O_NONBLOCK */
    call6(24, serial, 0, 0, 0, 0, 0);
    call6(24, serial, 1, 0, 0, 0, 0);
    call6(24, serial, 2, 0, 0, 0, 0);
    char *const args[] = {(char *)"sh", (char *)"-i", 0};
    char *const env[] = {(char *)"PATH=/system/bin:/system/xbin", 0};
    call6(221, (s64)"/system/bin/sh", (s64)args, (s64)env, 0, 0, 0);
    say(serial, "SHELL_EXEC_FAIL\r\n");
    fatal();
}
