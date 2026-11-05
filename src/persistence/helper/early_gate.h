#ifndef LIDAR_EARLY_GATE_H
#define LIDAR_EARLY_GATE_H

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

/* Fixed-purpose, opt-in per-boot WiFi gate. No caller-controlled command or
 * destination reaches the shell. A failed continuous gate leaves WiFi off. */
#define GATE_DIR "/data/user_de/0/org.local.lidar.binderprobe/files"
#define GATE_REQUEST GATE_DIR "/early_gate_request_v151"
#define GATE_GUARD GATE_DIR "/autoroot_attempt_boot_v149"
#define GATE_READY GATE_DIR "/early_gate_ready_v151"
#define GATE_LOG "/data/lidar-early-gate-v151.log"
#define GATE_IP4 "/system/bin/iptables"
#define GATE_IP6 "/system/bin/ip6tables"
#define GATE_CHAIN4 "L2EG4"
#define GATE_CHAIN6 "L2EG6"
#define GATE_KIOSK "me.jxl.kiosk_satellite"

enum gate_mode { GATE_OFF = 0, GATE_TRIAL = 1, GATE_CONTINUOUS = 2 };

/* Literal stock environment from /init.environ.rc. The tiny USB root
 * broker does not inherit these. No shell or caller input reaches argv. */
#define GATE_BOOTCLASSPATH "/system/framework/core-oj.jar:/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/core-junit.jar:/system/framework/bouncycastle.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/apache-xml.jar:/system/framework/nullwebview.jar:/system/framework/org.apache.http.legacy.boot.jar:/system/framework/fosframework.jar:/system/framework/dolby_ds.jar:/system/framework/dolby_ds2.jar"

static int gate_read_small(const char *path, char *output, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 1 ||
        st.st_size >= (off_t)capacity) {
        close(fd);
        return -EINVAL;
    }
    size_t used = 0;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, output + used, (size_t)st.st_size - used);
        if (n <= 0) { close(fd); return -EIO; }
        used += (size_t)n;
    }
    close(fd);
    output[used] = 0;
    return 0;
}

static int gate_requested_boot(unsigned *boot_count, enum gate_mode *mode) {
    char request[80], guard[80], expected[80];
    if (gate_read_small(GATE_REQUEST, request, sizeof(request)) != 0)
        return 0; /* Ordinary boot: preserve the v162 path. */
    if (sscanf(request, "boot_count=%u\n", boot_count) != 1) return -EINVAL;
    int size = snprintf(expected, sizeof(expected), "boot_count=%u\nmode=trial\n", *boot_count);
    if (size > 0 && (size_t)size < sizeof(expected) && strcmp(request, expected) == 0)
        *mode = GATE_TRIAL;
    else {
        size = snprintf(expected, sizeof(expected),
            "boot_count=%u\nmode=continuous\n", *boot_count);
        if (size < 1 || (size_t)size >= sizeof(expected) || strcmp(request, expected))
            return -EINVAL;
        *mode = GATE_CONTINUOUS;
    }
    if (*boot_count > 1000000000U)
        return -EINVAL;
    if (gate_read_small(GATE_GUARD, guard, sizeof(guard)) != 0) return -EINVAL;
    size = snprintf(expected, sizeof(expected), "%u:early", *boot_count);
    if (size < 1 || (size_t)size >= sizeof(expected) || strcmp(guard, expected))
        return -EINVAL;
    return 1;
}

static int gate_kiosk_uid(void) {
    int fd = open("/data/system/packages.list", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    FILE *input = fdopen(fd, "r");
    if (!input) { int error = errno; close(fd); return -error; }
    char line[512], name[160];
    long uid;
    int result = 0; /* No Kiosk installation: permit no app UID to reach WAN. */
    while (fgets(line, sizeof(line), input)) {
        if (sscanf(line, "%159s %ld", name, &uid) == 2 &&
            strcmp(name, GATE_KIOSK) == 0) {
            result = uid >= 10000 && uid <= 19999 ? (int)uid : -ERANGE;
            break;
        }
    }
    fclose(input);
    return result;
}

static int gate_run(const char *const argv[]) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        int log = open(GATE_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (log >= 0) {
            dup2(log, STDOUT_FILENO);
            dup2(log, STDERR_FILENO);
            if (log > STDERR_FILENO) close(log);
        }
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    int status = 0;
    for (int i = 0; i < 50; ++i) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
        if (done < 0) return -errno;
        usleep(100000);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return -ETIMEDOUT;
}

/* Stock settings is a script without a shebang. Run it through the stock
 * shell as UID 2000 in the shell domain, the context proven to reach the
 * settings provider. Only the fixed get/put global keys below are used. */
static int gate_settings(const char *verb, const char *key, const char *value,
                         char result[32]) {
    int output[2];
    if (pipe2(output, O_CLOEXEC) != 0) return -errno;
    pid_t child = fork();
    if (child < 0) {
        int error = errno;
        close(output[0]); close(output[1]);
        return -error;
    }
    if (child == 0) {
        close(output[0]);
        dup2(output[1], STDOUT_FILENO);
        close(output[1]);
        int log = open(GATE_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (log >= 0) {
            dup2(log, STDERR_FILENO);
            if (log > STDERR_FILENO) close(log);
        }
        int attr = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
        const char target[] = "u:r:shell:s0";
        if (attr < 0 || write(attr, target, sizeof(target) - 1) !=
            (ssize_t)(sizeof(target) - 1)) _exit(126);
        close(attr);
        if (setgid(2000) != 0 || setuid(2000) != 0) _exit(126);
        char *const argv[] = {"sh", "/system/bin/settings", (char *)verb,
                              "global", (char *)key, (char *)value, NULL};
        char *const envp[] = {"ANDROID_DATA=/data", "ANDROID_ROOT=/system",
                              "BOOTCLASSPATH=" GATE_BOOTCLASSPATH,
                              "PATH=/system/bin", NULL};
        execve("/system/bin/sh", argv, envp);
        _exit(127);
    }
    close(output[1]);
    int status = 0;
    int complete = 0;
    for (int i = 0; i < 50; ++i) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) { complete = 1; break; }
        if (done < 0) break;
        usleep(100000);
    }
    if (!complete) {
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        close(output[0]);
        return -ETIMEDOUT;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        close(output[0]);
        return -EIO;
    }
    if (result) {
        ssize_t length = read(output[0], result, 31);
        if (length < 0) { int error = errno; close(output[0]); return -error; }
        result[length] = 0;
    }
    close(output[0]);
    return 0;
}

static int gate_settings_integer(const char *key, unsigned *number) {
    char output[32] = {0};
    int result = gate_settings("get", key, NULL, output);
    if (result != 0) return result;
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(output, &end, 10);
    if (errno || end == output || (*end != '\n' && *end != 0) ||
        parsed > 1000000000UL) return -EINVAL;
    *number = (unsigned)parsed;
    return 0;
}

static int gate_settings_wifi(unsigned expected) {
    if (expected > 1) return -EINVAL;
    int result = gate_settings("put", "wifi_on", expected ? "1" : "0", NULL);
    if (result != 0) return result;
    unsigned observed = 2;
    result = gate_settings_integer("wifi_on", &observed);
    return result != 0 ? result : observed == expected ? 0 : -EIO;
}

static int gate_has_wlan_ipv4(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    struct ifreq address = {0};
    strncpy(address.ifr_name, "wlan0", IFNAMSIZ - 1);
    int okay = ioctl(fd, SIOCGIFADDR, &address) == 0 &&
        ((struct sockaddr_in *)&address.ifr_addr)->sin_addr.s_addr != 0;
    close(fd);
    return okay;
}

/* Limit Kiosk's web interface to the directly connected private WiFi subnet.
 * The interface address is assigned only after the gate has let WiFi up. */
static int gate_kiosk_subnet(char output[32]) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;
    struct ifreq address = {0}, netmask = {0};
    strncpy(address.ifr_name, "wlan0", IFNAMSIZ - 1);
    strncpy(netmask.ifr_name, "wlan0", IFNAMSIZ - 1);
    int okay = ioctl(fd, SIOCGIFADDR, &address) == 0 &&
               ioctl(fd, SIOCGIFNETMASK, &netmask) == 0;
    int saved = errno;
    close(fd);
    if (!okay) return -saved;
    uint32_t ip = ntohl(((struct sockaddr_in *)&address.ifr_addr)->sin_addr.s_addr);
    uint32_t mask = ntohl(((struct sockaddr_in *)&netmask.ifr_netmask)->sin_addr.s_addr);
    uint32_t inverse = ~mask;
    unsigned prefix = (unsigned)__builtin_popcount(mask);
    if ((inverse & (inverse + 1U)) != 0 || prefix < 16 || prefix > 30)
        return -EINVAL;
    if ((ip & 0xff000000U) != 0x0a000000U &&
        (ip & 0xfff00000U) != 0xac100000U &&
        (ip & 0xffff0000U) != 0xc0a80000U) return -EACCES;
    struct in_addr network = { .s_addr = htonl(ip & mask) };
    char address_text[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &network, address_text, sizeof(address_text)))
        return -errno;
    int size = snprintf(output, 32, "%s/%u", address_text, prefix);
    return size > 0 && size < 32 ? 0 : -ENOSPC;
}

static int gate_allow_kiosk_web(void) {
    if (gate_kiosk_uid() <= 0) return 0;
    char subnet[32];
    int result = gate_kiosk_subnet(subnet);
    if (result != 0) return result;
    const char *const check[] = {GATE_IP4, "-C", "INPUT", "-i", "wlan0",
        "-s", subnet, "-p", "tcp", "--dport", "2324", "-j", "ACCEPT", NULL};
    if (gate_run(check) == 0) return 0;
    const char *const insert[] = {GATE_IP4, "-I", "INPUT", "1", "-i", "wlan0",
        "-s", subnet, "-p", "tcp", "--dport", "2324", "-j", "ACCEPT", NULL};
    if (gate_run(insert) != 0 || gate_run(check) != 0) return -EIO;
    return 0;
}

#define GATE_V4(...) gate_run((const char *const[]){GATE_IP4, "-t", "mangle", __VA_ARGS__, NULL})
#define GATE_V6(...) gate_run((const char *const[]){GATE_IP6, "-t", "mangle", __VA_ARGS__, NULL})

static void gate_cleanup(void) {
    (void)GATE_V6("-D", "OUTPUT", "-j", GATE_CHAIN6);
    (void)GATE_V4("-D", "OUTPUT", "-j", GATE_CHAIN4);
    (void)GATE_V6("-F", GATE_CHAIN6);
    (void)GATE_V4("-F", GATE_CHAIN4);
    (void)GATE_V6("-X", GATE_CHAIN6);
    (void)GATE_V4("-X", GATE_CHAIN4);
}

/* In trial mode only, restore the original boot preference and remove the
 * filter after 120 seconds. USB and the proven rescue APK remain required
 * because the settings command under this domain is not hardware-tested. */
static int gate_start_trial_timer(pid_t *timer) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        (void)setsid();
        for (int fd = 0; fd < 64; ++fd) close(fd);
        int null = open("/dev/null", O_RDWR);
        if (null >= 0) {
            dup2(null, STDIN_FILENO);
            dup2(null, STDOUT_FILENO);
            dup2(null, STDERR_FILENO);
            if (null > STDERR_FILENO) close(null);
        }
        sleep(120);
        int setting = gate_settings_wifi(1);
        int log = open(GATE_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (log >= 0) {
            char line[96];
            int length = snprintf(line, sizeof(line),
                "GATE_TRIAL_REVERT wifi_on_rc=%d\n", setting);
            if (length > 0 && (size_t)length < sizeof(line))
                (void)write(log, line, (size_t)length);
            close(log);
        }
        unlink(GATE_READY);
        gate_cleanup();
        _exit(0);
    }
    *timer = child;
    return 0;
}

static int gate_publish(unsigned boot_count, enum gate_mode mode, int kiosk_uid) {
    char next[256], value[96];
    int size = snprintf(next, sizeof(next), "%s.tmp.%ld", GATE_READY, (long)getpid());
    if (size < 1 || (size_t)size >= sizeof(next)) return -ENAMETOOLONG;
    size = snprintf(value, sizeof(value),
        "boot_count=%u\nmode=%s\nfilter=ready\nkiosk_uid=%d\n",
        boot_count, mode == GATE_TRIAL ? "trial" : "continuous", kiosk_uid);
    if (size < 1 || (size_t)size >= sizeof(value)) return -EOVERFLOW;
    int fd = open(next, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) return -errno;
    int okay = write(fd, value, (size_t)size) == size &&
        fchmod(fd, 0644) == 0 && fsync(fd) == 0;
    int saved = errno;
    close(fd);
    if (!okay) {
        unlink(next);
        return saved ? -saved : -EIO;
    }
    if (rename(next, GATE_READY) != 0) {
        saved = errno;
        unlink(next);
        return -saved;
    }
    return 0;
}

static int gate_install(unsigned boot_count, enum gate_mode mode, int kiosk_uid) {
    char uid[16];
    pid_t timer = -1;
    snprintf(uid, sizeof(uid), "%d", kiosk_uid);
    if (GATE_V4("-N", GATE_CHAIN4) != 0) return -1;
    if (GATE_V6("-N", GATE_CHAIN6) != 0) {
        (void)GATE_V4("-F", GATE_CHAIN4);
        (void)GATE_V4("-X", GATE_CHAIN4);
        return -1;
    }
    /* Keep common private LANs reachable without embedding one home's
     * address. Public destinations still need the single allowed app UID. */
    if (GATE_V4("-A", GATE_CHAIN4, "-o", "wlan0", "-d", "10.0.0.0/8", "-j", "RETURN") != 0 ||
        GATE_V4("-A", GATE_CHAIN4, "-o", "wlan0", "-d", "172.16.0.0/12", "-j", "RETURN") != 0 ||
        GATE_V4("-A", GATE_CHAIN4, "-o", "wlan0", "-d", "192.168.0.0/16", "-j", "RETURN") != 0 ||
        GATE_V4("-A", GATE_CHAIN4, "-o", "wlan0", "-d", "224.0.0.0/4", "-j", "RETURN") != 0 ||
        GATE_V4("-A", GATE_CHAIN4, "-o", "wlan0", "-d", "255.255.255.255/32", "-j", "RETURN") != 0) goto fail;
    if (kiosk_uid > 0 &&
        GATE_V4("-A", GATE_CHAIN4, "-o", "wlan0", "-m", "owner", "--uid-owner", uid, "-j", "RETURN") != 0)
        goto fail;
    if (GATE_V4("-A", GATE_CHAIN4, "-o", "wlan0", "-j", "DROP") != 0 ||
        GATE_V6("-A", GATE_CHAIN6, "-o", "wlan0", "-d", "fe80::/10", "-j", "RETURN") != 0 ||
        GATE_V6("-A", GATE_CHAIN6, "-o", "wlan0", "-d", "fc00::/7", "-j", "RETURN") != 0 ||
        GATE_V6("-A", GATE_CHAIN6, "-o", "wlan0", "-d", "ff00::/8", "-j", "RETURN") != 0) goto fail;
    if (kiosk_uid > 0 &&
        GATE_V6("-A", GATE_CHAIN6, "-o", "wlan0", "-m", "owner", "--uid-owner", uid, "-j", "RETURN") != 0)
        goto fail;
    if (GATE_V6("-A", GATE_CHAIN6, "-o", "wlan0", "-j", "DROP") != 0 ||
        GATE_V4("-I", "OUTPUT", "1", "-j", GATE_CHAIN4) != 0 ||
        GATE_V6("-I", "OUTPUT", "1", "-j", GATE_CHAIN6) != 0 ||
        GATE_V4("-C", "OUTPUT", "-j", GATE_CHAIN4) != 0 ||
        GATE_V6("-C", "OUTPUT", "-j", GATE_CHAIN6) != 0 ||
        GATE_V4("-C", GATE_CHAIN4, "-o", "wlan0", "-j", "DROP") != 0 ||
        GATE_V6("-C", GATE_CHAIN6, "-o", "wlan0", "-j", "DROP") != 0 ||
        (mode == GATE_TRIAL && gate_start_trial_timer(&timer) != 0) ||
        gate_publish(boot_count, mode, kiosk_uid) != 0) goto fail;
    return 0;
fail:
    if (timer > 0) { kill(timer, SIGTERM); waitpid(timer, NULL, 0); }
    gate_cleanup();
    return -1;
}

static int gate_setup_after_root(void) {
    unsigned boot_count = 0;
    enum gate_mode mode = GATE_OFF;
    int requested = gate_requested_boot(&boot_count, &mode);
    if (requested <= 0) return requested; /* 0 means gate not armed. */
    /* A filter attached after DHCP cannot prove early isolation. */
    if (gate_has_wlan_ipv4()) return -EALREADY;
    unsigned live_count = 0;
    if (gate_settings_integer("boot_count", &live_count) != 0 ||
        live_count != boot_count) return -EINVAL;
    if (unlink(GATE_READY) != 0 && errno != ENOENT) return -errno;
    int kiosk_uid = gate_kiosk_uid();
    if (kiosk_uid < 0) return kiosk_uid;
    return gate_install(boot_count, mode, kiosk_uid) == 0 ? (int)mode : -EIO;
}

/* Independent, same-boot readback for the app before it opens Wi-Fi. The
 * app-private ready file alone is not an authorization boundary. */
static int gate_check_filter(void) {
    unsigned requested_count = 0, live_count = 0;
    enum gate_mode mode = GATE_OFF;
    if (gate_requested_boot(&requested_count, &mode) != 1 ||
        gate_settings_integer("boot_count", &live_count) != 0 ||
        requested_count != live_count) return -EINVAL;
    int kiosk_uid = gate_kiosk_uid();
    if (kiosk_uid < 0) return kiosk_uid;
    char ready[128], expected[128], uid[16];
    int length = snprintf(expected, sizeof(expected),
        "boot_count=%u\nmode=%s\nfilter=ready\nkiosk_uid=%d\n",
        requested_count, mode == GATE_TRIAL ? "trial" : "continuous", kiosk_uid);
    if (length < 1 || (size_t)length >= sizeof(expected) ||
        gate_read_small(GATE_READY, ready, sizeof(ready)) != 0 ||
        strcmp(ready, expected) != 0) return -EINVAL;
    snprintf(uid, sizeof(uid), "%d", kiosk_uid);
    if (GATE_V4("-C", "OUTPUT", "-j", GATE_CHAIN4) != 0 ||
        GATE_V6("-C", "OUTPUT", "-j", GATE_CHAIN6) != 0 ||
        GATE_V4("-C", GATE_CHAIN4, "-o", "wlan0", "-j", "DROP") != 0 ||
        GATE_V6("-C", GATE_CHAIN6, "-o", "wlan0", "-j", "DROP") != 0)
        return -EINVAL;
    if (kiosk_uid > 0 &&
        (GATE_V4("-C", GATE_CHAIN4, "-o", "wlan0", "-m", "owner", "--uid-owner", uid, "-j", "RETURN") != 0 ||
         GATE_V6("-C", GATE_CHAIN6, "-o", "wlan0", "-m", "owner", "--uid-owner", uid, "-j", "RETURN") != 0))
        return -EINVAL;
    return 0;
}

/* The app's fixed GATE_PERSIST request is accepted only after the same
 * boot's checked filter is active and wlan0 has an IPv4 address. */
static int gate_persist_wifi_off(void) {
    int verified = gate_check_filter();
    if (verified != 0) return verified;
    if (!gate_has_wlan_ipv4()) return -ENETDOWN;
    int result = gate_settings_wifi(0);
    if (result != 0) return result;
    if (!gate_has_wlan_ipv4()) {
        (void)gate_settings_wifi(1);
        return -ENETDOWN;
    }
    int kiosk_web = gate_allow_kiosk_web();
    int log = open(GATE_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (log >= 0) {
        dprintf(log, "KIOSK_WEB_LAN port=2324 rc=%d\n", kiosk_web);
        close(log);
    }
    /* A Kiosk web failure must not take down the independent WiFi gate. */
    return 0;
}

#endif
