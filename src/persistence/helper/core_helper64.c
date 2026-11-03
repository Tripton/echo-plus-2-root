#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "sha256.h"

#define APP_UID_MIN 10000
#define APP_UID_MAX 19999
#define SOCKET_PATH "/data/data/org.local.lidar.binderprobe/files/root-v146.sock"
#define SHELL_UID 2000
#define SHELL_SOCKET_PATH "/data/local/tmp/lidar-root-v154.sock"
#define MARKER_PATH "/data/lidar-root-v154.marker"
#define PROPERTY_LOG_PATH "/data/lidar-root-v154-properties.log"
#define CONTEXT_LOG_PATH "/data/lidar-root-v154-context.log"
#define MIC_HELPER_PATH "/data/lidar-kiosk-mic-keeper"
#define MIC_HELPER_LOG "/data/lidar-kiosk-mic-keeper.log"
#ifndef MIC_HELPER_SHA256
#error Build the microphone worker before compiling the root helper.
#endif
#ifndef MIC_HELPER_SIZE
#error The microphone worker size must be embedded in the root helper.
#endif
#define AMAZON_STOP_LOG "/data/lidar-amazon-stop-v159.log"
#define BUTTON_HELPER_PATH "/data/lidar-kiosk-buttons"
#define BUTTON_HELPER_LOG "/data/lidar-kiosk-buttons.log"
#ifndef BUTTON_HELPER_SHA256
#error Build the button worker before compiling the root helper.
#endif
#ifndef BUTTON_HELPER_SIZE
#error The button worker size must be embedded in the root helper.
#endif
#define NETWORK_CONFIG_PATH "/data/lidar-network-adb.conf"
#define NETWORK_LOG_PATH "/data/lidar-network-adb.log"
#define ADB_KEYS_PATH "/data/misc/adb/adb_keys"
#define AMAZON_LOCKDOWN_PATH "/data/lidar-amazon-lockdown.conf"
#include "early_gate.h"

/* Only the exact root-owned setting can request the three fixed init stops.
 * A missing or malformed setting leaves stock services alone. */
static int amazon_lockdown_enabled(void) {
    int fd = open(AMAZON_LOCKDOWN_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    struct stat st;
    const char expected[] = "enabled=1\n";
    char value[sizeof(expected)] = {0};
    int valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                st.st_uid == 0 && st.st_gid == 0 &&
                (st.st_mode & 0777) == 0600 &&
                st.st_size == (off_t)(sizeof(expected) - 1) &&
                read(fd, value, sizeof(expected) - 1) ==
                    (ssize_t)(sizeof(expected) - 1) &&
                memcmp(value, expected, sizeof(expected) - 1) == 0;
    close(fd);
    return valid;
}

/* A root-owned local setting enables only the stock, UID-2000 adbd. The
 * corresponding host key hash must match Android's authorized-key file.
 * This is a normal-shell transport, never a network Root broker. */
static int network_config_key(char expected[65]) {
    int fd = open(NETWORK_CONFIG_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? 0 : -errno;
    struct stat statbuf;
    if (fstat(fd, &statbuf) || !S_ISREG(statbuf.st_mode) ||
        statbuf.st_uid != 0 || statbuf.st_gid != 0 ||
        (statbuf.st_mode & 0777) != 0600 || statbuf.st_size != 86) {
        close(fd); return -EINVAL;
    }
    char contents[87] = {0};
    ssize_t count = read(fd, contents, 86);
    close(fd);
    if (count != 86 || memcmp(contents, "enabled=1\nkey_sha256=", 21) ||
        contents[85] != '\n') return -EINVAL;
    for (int i = 0; i < 64; ++i) {
        char c = contents[21 + i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return -EINVAL;
        expected[i] = c;
    }
    expected[64] = 0;
    return 1;
}

static int authorized_key_matches(const char expected[65]) {
    char secure[8] = {0}, production[8] = {0}, debuggable[8] = {0};
    __system_property_get("ro.adb.secure", secure);
    __system_property_get("ro.secure", production);
    __system_property_get("ro.debuggable", debuggable);
    if (strcmp(secure, "1") || strcmp(production, "1") ||
        strcmp(debuggable, "0")) return -EPERM;
    int fd = open(ADB_KEYS_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    struct stat statbuf;
    if (fstat(fd, &statbuf) || !S_ISREG(statbuf.st_mode) ||
        statbuf.st_uid != 1000 || statbuf.st_gid != 2000 ||
        (statbuf.st_mode & 0777) != 0640 ||
        statbuf.st_size < 200 || statbuf.st_size > 8192) {
        close(fd); return -EINVAL;
    }
    sha256_context hash;
    sha256_init(&hash);
    char buffer[1024];
    ssize_t count;
    while ((count = read(fd, buffer, sizeof(buffer))) > 0)
        sha256_update(&hash, buffer, (size_t)count);
    close(fd);
    if (count < 0) return -errno;
    unsigned char bytes[32];
    sha256_final(&hash, bytes);
    static const char digits[] = "0123456789abcdef";
    char actual[65];
    for (int i = 0; i < 32; ++i) {
        actual[2 * i] = digits[bytes[i] >> 4];
        actual[2 * i + 1] = digits[bytes[i] & 15];
    }
    actual[64] = 0;
    return strcmp(actual, expected) == 0 ? 0 : -EBADMSG;
}

/* The optional microphone worker is a distinct, fixed-purpose binary. It
 * grants RECORD_AUDIO only to the installed Kiosk package when requested.
 * Refuse a substitute helper; failure never disables the existing root and
 * USB recovery path. /data is root-owned and the helper must be root-only. */
static int verified_mic_helper(void) {
    int fd=open(MIC_HELPER_PATH,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -errno;
    struct stat before, after, current;
    if (fstat(fd,&before)!=0 || !S_ISREG(before.st_mode) ||
        before.st_uid!=0 || before.st_gid!=0 ||
        (before.st_mode & 0777)!=0500 || before.st_size!=MIC_HELPER_SIZE) {
        close(fd); return -EINVAL;
    }
    sha256_context hash;
    sha256_init(&hash);
    char buffer[32768];
    ssize_t count;
    while ((count=read(fd,buffer,sizeof(buffer)))>0)
        sha256_update(&hash,buffer,(size_t)count);
    if (count<0 || fstat(fd,&after)!=0 || lstat(MIC_HELPER_PATH,&current)!=0) {
        int saved=errno; close(fd); return -saved;
    }
    close(fd);
    if (before.st_dev!=after.st_dev || before.st_ino!=after.st_ino ||
        before.st_size!=after.st_size || before.st_mtime!=after.st_mtime ||
        current.st_dev!=after.st_dev || current.st_ino!=after.st_ino)
        return -EAGAIN;
    unsigned char bytes[32];
    sha256_final(&hash,bytes);
    static const char digits[]="0123456789abcdef";
    char hex[65];
    for (unsigned i=0;i<32;++i) {
        hex[2*i]=digits[bytes[i]>>4];
        hex[2*i+1]=digits[bytes[i]&15];
    }
    hex[64]=0;
    return strcmp(hex,MIC_HELPER_SHA256)==0 ? 0 : -EBADMSG;
}

static int start_mic_worker(void) {
    int verified=verified_mic_helper();
    if (verified!=0) return verified;
    pid_t child=fork();
    if (child<0) return -errno;
    if (child==0) {
        if (setsid()<0) _exit(31);
        for (int fd=0;fd<64;++fd) close(fd);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if (null>=0) {
            dup2(null,0); dup2(null,1); dup2(null,2);
            if (null>2) close(null);
        }
        int log=open(MIC_HELPER_LOG,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
        if (log>=0) {
            dup2(log,1); dup2(log,2);
            if (log>2) close(log);
        }
        char *const arguments[]={"kiosk_mic_keeper",NULL};
        char *const environment[]={
            "PATH=/system/bin","LANG=C","ANDROID_DATA=/data",
            "ANDROID_ROOT=/system",NULL
        };
        execve(MIC_HELPER_PATH,arguments,environment);
        dprintf(2,"MIC_WORKER_EXEC_FAILED errno=%d\n",errno);
        _exit(127);
    }
    return 0;
}

/* Fixed-purpose bridge from the Plus 2 GPIO keys to the local Kiosk plugin.
 * The bridge only reads the two named input nodes and sends A/M to a local
 * abstract socket. No external command, address or path is accepted. */
static int verified_button_helper(void) {
    int fd=open(BUTTON_HELPER_PATH,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -errno;
    struct stat before, after, current;
    if (fstat(fd,&before)!=0 || !S_ISREG(before.st_mode) ||
        before.st_uid!=0 || before.st_gid!=0 ||
        (before.st_mode & 0777)!=0500 || before.st_size!=BUTTON_HELPER_SIZE) {
        close(fd); return -EINVAL;
    }
    sha256_context hash;
    sha256_init(&hash);
    char buffer[32768];
    ssize_t count;
    while ((count=read(fd,buffer,sizeof(buffer)))>0)
        sha256_update(&hash,buffer,(size_t)count);
    if (count<0 || fstat(fd,&after)!=0 || lstat(BUTTON_HELPER_PATH,&current)!=0) {
        int saved=errno; close(fd); return -saved;
    }
    close(fd);
    if (before.st_dev!=after.st_dev || before.st_ino!=after.st_ino ||
        before.st_size!=after.st_size || before.st_mtime!=after.st_mtime ||
        current.st_dev!=after.st_dev || current.st_ino!=after.st_ino)
        return -EAGAIN;
    unsigned char bytes[32];
    sha256_final(&hash,bytes);
    static const char digits[]="0123456789abcdef";
    char hex[65];
    for (unsigned i=0;i<32;++i) {
        hex[2*i]=digits[bytes[i]>>4];
        hex[2*i+1]=digits[bytes[i]&15];
    }
    hex[64]=0;
    return strcmp(hex,BUTTON_HELPER_SHA256)==0 ? 0 : -EBADMSG;
}

static int start_button_worker(void) {
    int verified=verified_button_helper();
    if (verified!=0) return verified;
    pid_t child=fork();
    if (child<0) return -errno;
    if (child==0) {
        if (setsid()<0) _exit(31);
        for (int fd=0;fd<64;++fd) close(fd);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if (null>=0) {
            dup2(null,0); dup2(null,1); dup2(null,2);
            if (null>2) close(null);
        }
        int log=open(BUTTON_HELPER_LOG,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
        if (log>=0) {
            dup2(log,1); dup2(log,2);
            if (log>2) close(log);
        }
        char *const arguments[]={"echo_plus2_key_forwarder","--forever",NULL};
        char *const environment[]={
            "PATH=/system/bin","LANG=C","ANDROID_DATA=/data",
            "ANDROID_ROOT=/system",NULL
        };
        execve(BUTTON_HELPER_PATH,arguments,environment);
        dprintf(2,"BUTTON_WORKER_EXEC_FAILED errno=%d\n",errno);
        _exit(127);
    }
    return 0;
}

/* Run the setprop binary that belongs to this Android 7 build. The static
 * bionic property API used by v149 returned success without changing the
 * values when invoked from the stock core helper. Bound each child to 4 s. */
static int stock_setprop(const char *name, const char *value) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        int evidence = open(CONTEXT_LOG_PATH,
                            O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (evidence >= 0) {
            dup2(evidence, STDOUT_FILENO);
            dup2(evidence, STDERR_FILENO);
            if (evidence > STDERR_FILENO) close(evidence);
        }
        execl("/system/bin/setprop", "setprop", name, value, (char *)NULL);
        dprintf(STDERR_FILENO, "exec_setprop_errno=%d\n", errno);
        _exit(127);
    }
    for (int i = 0; i < 40; ++i) {
        int status = 0;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -2;
        if (result < 0) return -errno;
        usleep(100000);
    }
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return -3;
}

/* The kernel SELinux domain can return success from setprop without the
 * property service applying a change. Use the init transition proved by
 * the stock-service stop path and the live property probe. */
static int init_setprop(const char *name, const char *value) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        execl("/system/bin/runcon", "runcon", "u:r:init:s0",
              "/system/bin/setprop", name, value, (char *)NULL);
        _exit(127);
    }
    int status = -1;
    for (int i = 0; i < 40; ++i) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) break;
        if (done < 0) return -errno;
        usleep(100000);
    }
    if (status == -1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return -ETIMEDOUT;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}

static int restart_stock_adbd(void) {
    return init_setprop("ctl.restart", "adbd");
}

static int listener_in(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        char index[32], local[80], remote[80], state[8];
        if (sscanf(line, "%31s %79s %79s %7s", index, local, remote, state) != 4 ||
            strcmp(state, "0A")) continue;
        const char *colon = strrchr(local, ':');
        if (colon && strcmp(colon + 1, "15B3") == 0) {
            found = 1; break;
        }
    }
    fclose(file);
    return found;
}

static int network_listener_ready(void) {
    return listener_in("/proc/net/tcp") || listener_in("/proc/net/tcp6");
}

static void network_log(int config, int key, int property, int restart,
                        int listener, int rollback) {
    int fd = open(NETWORK_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC |
                  O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    dprintf(fd, "NETWORK_ADB_V162 config=%d key=%d property=%d restart=%d "
            "listener=%d rollback=%d\n",
            config, key, property, restart, listener, rollback);
    fsync(fd);
    close(fd);
}

/* Android's property service rejects ctl.* from the inherited kernel
 * context, even though the exploit makes the kernel SELinux policy
 * permissive. A fixed init-context child may stop these three named stock
 * services. No command, path or service name comes from an external client. */
static int stop_stock_service(const char *name) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        execl("/system/bin/runcon", "runcon", "u:r:init:s0",
              "/system/bin/setprop", "ctl.stop", name, (char *)NULL);
        _exit(127);
    }
    int status = -1;
    for (int i = 0; i < 40; ++i) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) break;
        if (done < 0) return -errno;
        usleep(100000);
    }
    if (status == -1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return -ETIMEDOUT;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return -EIO;
    char property[64];
    if (snprintf(property, sizeof(property), "init.svc.%s", name) >=
        (int)sizeof(property)) return -ENAMETOOLONG;
    char value[64];
    for (int i = 0; i < 20; ++i) {
        value[0] = 0;
        __system_property_get(property, value);
        if (strcmp(value, "stopped") == 0) return 0;
        usleep(100000);
    }
    return -EAGAIN;
}

static void write_amazon_stop_log(int update_rc, int ahe_rc, int filed_rc) {
    int fd = open(AMAZON_STOP_LOG,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) return;
    dprintf(fd, "AMAZON_STOP_V159 uid=%ld update_engine_rc=%d ahe_rc=%d amazonfiled_rc=%d\n",
            (long)getuid(), update_rc, ahe_rc, filed_rc);
    fsync(fd);
    close(fd);
}

static void current_context(char out[128]) {
    strcpy(out, "unavailable");
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t count = read(fd, out, 127);
    if (count > 0) out[count] = 0;
    close(fd);
}

/* Test a process-local SELinux transition without changing global enforcing.
 * Only a successful transition and verified TCP-disable permits the USB mode
 * change. The parent/root broker retain their original security context. */
static int context_probe(void) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        char before[128], after[128];
        current_context(before);
        int attr = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
        int written = -1;
        int saved_errno = attr < 0 ? errno : 0;
        if (attr >= 0) {
            const char target[] = "u:r:init:s0";
            written = (int)write(attr, target, sizeof(target) - 1);
            saved_errno = written < 0 ? errno : 0;
            close(attr);
        }
        current_context(after);
        char tcp[64] = "unset", tcp_immediate[64] = "unset";
        char usb[64] = "unset", harmless[64] = "unset";
        int harmless_rc = -1, tcp_rc = -1, usb_rc = -1;
        if (written == 11 && strstr(after, "u:r:init:s0") == after) {
            /* Call bionic directly while this child is still in init:s0.
             * The previous test called an external setprop process, whose
             * SELinux domain after exec is not established. */
            harmless_rc = __system_property_set("sys.lidar.root_probe", "v154");
            __system_property_get("sys.lidar.root_probe", harmless);
            tcp_rc = __system_property_set("service.adb.tcp.port", "-1");
            __system_property_get("service.adb.tcp.port", tcp_immediate);
            usleep(300000);
            __system_property_get("service.adb.tcp.port", tcp);
            if (tcp_rc == 0 && strcmp(tcp, "-1") == 0) {
                usb_rc = __system_property_set("sys.usb.config", "mtp,adb");
                usleep(300000);
                __system_property_get("sys.usb.config", usb);
            }
        }
        int log = open(CONTEXT_LOG_PATH,
                       O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (log >= 0) {
            dprintf(log,
                    "CONTEXT_PROBE_V154 before=%s after=%s write=%d errno=%d "
                    "harmless_rc=%d harmless=%s tcp_rc=%d tcp_immediate=%s tcp=%s "
                    "usb_rc=%d usb=%s\n",
                    before, after, written, saved_errno,
                    harmless_rc, harmless, tcp_rc, tcp_immediate, tcp,
                    usb_rc, usb);
            fsync(log);
            close(log);
        }
        _exit(0);
    }
    for (int i = 0; i < 200; ++i) {
        int status = 0;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -2;
        if (result < 0) return -errno;
        usleep(100000);
    }
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return -3;
}

static void property_snapshot(int attempt, int tcp_rc, int usb_rc) {
    char tcp[64] = "unset";
    char usb[64] = "unset";
    char state[64] = "unset";
    __system_property_get("service.adb.tcp.port", tcp);
    __system_property_get("sys.usb.config", usb);
    __system_property_get("sys.usb.state", state);
    int fd = open(PROPERTY_LOG_PATH,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) return;
    char line[256];
    int count = snprintf(line, sizeof(line),
                         "attempt=%d time=%ld tcp_rc=%d tcp=%s "
                         "usb_rc=%d usb=%s state=%s\n",
                         attempt, (long)time(NULL), tcp_rc, tcp,
                         usb_rc, usb, state);
    if (count > 0 && (size_t)count < sizeof(line)) write(fd, line, count);
    fsync(fd);
    close(fd);
}

static void property_worker(void) {
    /* A bounded follow-up reveals whether another stock service replaces the
     * settings. Stop after 30 seconds even if the USB mode never settles. */
    const unsigned delays[] = {0, 2, 4, 9, 15};
    for (int attempt = 0; attempt < 5; ++attempt) {
        sleep(delays[attempt]);
        char tcp[64] = {0};
        char usb[64] = {0};
        __system_property_get("service.adb.tcp.port", tcp);
        __system_property_get("sys.usb.config", usb);
        int tcp_rc = 0;
        int usb_rc = 0;
        if (strcmp(tcp, "-1") != 0) {
            tcp_rc = stock_setprop("service.adb.tcp.port", "-1");
            usleep(200000);
        }
        __system_property_get("service.adb.tcp.port", tcp);
        if (strcmp(tcp, "-1") == 0 && strcmp(usb, "mtp,adb") != 0) {
            usb_rc = stock_setprop("sys.usb.config", "mtp,adb");
            usleep(250000);
        }
        property_snapshot(attempt, tcp_rc, usb_rc);
    }
    char expected[65] = {0};
    int configured = network_config_key(expected);
    if (configured != 1) {
        network_log(configured, -1, -1, -1, 0, 0);
        return;
    }
    int key = authorized_key_matches(expected);
    if (key != 0) {
        network_log(configured, key, -1, -1, 0, 0);
        return;
    }
    /* Keep USB ADB active. A network listener is enabled only after the
     * original recovery transport settles and the authorized key matches. */
    int property = init_setprop("service.adb.tcp.port", "5555");
    char tcp[64] = {0};
    for (int i = 0; i < 30; ++i) {
        __system_property_get("service.adb.tcp.port", tcp);
        if (strcmp(tcp, "5555") == 0) break;
        usleep(100000);
    }
    int restart = property == 0 && strcmp(tcp, "5555") == 0 ?
                  restart_stock_adbd() : -1;
    int listener = 0;
    if (restart == 0) {
        for (int i = 0; i < 30; ++i) {
            if (network_listener_ready()) { listener = 1; break; }
            usleep(100000);
        }
    }
    int rollback = 0;
    if (!listener) {
        int reset = init_setprop("service.adb.tcp.port", "-1");
        int retry = restart_stock_adbd();
        rollback = reset == 0 && retry == 0 ? 1 : -1;
    }
    network_log(configured, key, property, restart, listener, rollback);
}

static int start_property_worker(void) {
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        if (setsid() < 0) _exit(31);
        for (int fd = 0; fd < 64; ++fd) close(fd);
        int null = open("/dev/null", O_RDWR);
        if (null >= 0) {
            dup2(null, 0); dup2(null, 1); dup2(null, 2);
            if (null > 2) close(null);
        }
        property_worker();
        _exit(0);
    }
    return 0;
}

/* ADB's authenticated shell may use USB or the pinned stock TCP listener.
 * The bounded root bridge itself exposes only a local Unix socket. */
static int shell_bridge_ready(void) {
    char tcp[64] = {0}, usb[64] = {0};
    __system_property_get("service.adb.tcp.port", tcp);
    __system_property_get("sys.usb.config", usb);
    if (strcmp(usb, "mtp,adb") != 0) return 0;
    if (strcmp(tcp, "-1") == 0) return 1;
    if (strcmp(tcp, "5555") != 0 || !network_listener_ready()) return 0;
    char expected[65] = {0};
    return network_config_key(expected) == 1 &&
           authorized_key_matches(expected) == 0;
}

static int shell_bridge_serve(void) {
    struct stat directory, old;
    if (stat("/data/local/tmp", &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != SHELL_UID || !shell_bridge_ready()) return 40;
    if (lstat(SHELL_SOCKET_PATH, &old) == 0) {
        if (!S_ISSOCK(old.st_mode) || old.st_uid != 0 ||
            unlink(SHELL_SOCKET_PATH)) return 41;
    } else if (errno != ENOENT) return 42;
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return 43;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (strlen(SHELL_SOCKET_PATH) >= sizeof(addr.sun_path)) return 44;
    strcpy(addr.sun_path, SHELL_SOCKET_PATH);
    mode_t previous = umask(077);
    int bound = bind(listener, (struct sockaddr *)&addr,
                     offsetof(struct sockaddr_un, sun_path) +
                     strlen(addr.sun_path) + 1);
    umask(previous);
    if (bound || chown(SHELL_SOCKET_PATH, 0, SHELL_UID) ||
        chmod(SHELL_SOCKET_PATH, 0660) || listen(listener, 1)) return 45;

    time_t deadline = time(NULL) + 900;
    int served = 0;
    while (time(NULL) < deadline && served < 16) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);
        struct timeval wait = { .tv_sec = 1, .tv_usec = 0 };
        int ready = select(listener + 1, &readfds, NULL, NULL, &wait);
        if (ready <= 0) continue;
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) continue;
        struct ucred peer;
        socklen_t size = sizeof(peer);
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
            size != sizeof(peer) || peer.uid != SHELL_UID ||
            peer.gid != SHELL_UID || !shell_bridge_ready()) {
            close(client);
            continue;
        }
        struct timeval io_timeout = { .tv_sec = 15, .tv_usec = 0 };
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &io_timeout, sizeof(io_timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &io_timeout, sizeof(io_timeout));
        char request[1024] = {0};
        size_t used = 0;
        while (used < sizeof(request) - 1) {
            ssize_t n = read(client, request + used, sizeof(request) - 1 - used);
            if (n <= 0) break;
            used += (size_t)n;
            if (memchr(request, '\n', used)) break;
        }
        if (used < 6 || memcmp(request, "RUN ", 4) ||
            request[used - 1] != '\n' || memchr(request, 0, used)) {
            dprintf(client, "BRIDGE_BAD_REQUEST\n");
            close(client);
            continue;
        }
        request[used - 1] = 0;
        pid_t child = fork();
        if (child == 0) {
            dup2(client, STDOUT_FILENO);
            dup2(client, STDERR_FILENO);
            close(client);
            close(listener);
            setenv("PATH", "/sbin:/system/bin:/vendor/bin", 1);
            execl("/system/bin/sh", "sh", "-c", request + 4, (char *)NULL);
            _exit(127);
        }
        int status = -1;
        if (child > 0) {
            for (int i = 0; i < 150; ++i) {
                pid_t result = waitpid(child, &status, WNOHANG);
                if (result == child || result < 0) break;
                usleep(100000);
            }
            if (status == -1) {
                kill(child, SIGKILL);
                waitpid(child, &status, 0);
            }
            dprintf(client, "BRIDGE_EXIT=%d\n",
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            served++;
        }
        close(client);
    }
    close(listener);
    unlink(SHELL_SOCKET_PATH);
    return 0;
}

static int start_shell_bridge(void) {
    if (!shell_bridge_ready()) return -1;
    pid_t child = fork();
    if (child < 0) return -errno;
    if (child == 0) {
        if (setsid() < 0) _exit(31);
        for (int fd = 0; fd < 64; ++fd) close(fd);
        int null = open("/dev/null", O_RDWR);
        if (null >= 0) {
            dup2(null, 0); dup2(null, 1); dup2(null, 2);
            if (null > 2) close(null);
        }
        _exit(shell_bridge_serve());
    }
    return 0;
}

static void write_marker(int restored, int property_result, int context_result,
                         int daemon_result,
                         int tcp_result, int usb_result, int worker_result,
                         int shell_bridge_result, int mic_worker_result,
                         int button_worker_result, int gate_result,
                         int argc, char **argv) {
    char context[128] = "unavailable";
    int attr = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (attr >= 0) {
        ssize_t count = read(attr, context, sizeof(context) - 1);
        if (count > 0) context[count] = 0;
        close(attr);
    }
    int fd = open(MARKER_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return;
    char tcp[64] = "unset";
    char usb[64] = "unset";
    char self_mnt[64] = "unavailable";
    char init_mnt[64] = "unavailable";
    ssize_t self_len = readlink("/proc/self/ns/mnt", self_mnt, sizeof(self_mnt) - 1);
    ssize_t init_len = readlink("/proc/1/ns/mnt", init_mnt, sizeof(init_mnt) - 1);
    if (self_len > 0) self_mnt[self_len] = 0;
    if (init_len > 0) init_mnt[init_len] = 0;
    struct stat property_socket;
    int socket_ok = stat("/dev/socket/property_service", &property_socket) == 0;
    int socket_error = socket_ok ? 0 : errno;
    __system_property_get("service.adb.tcp.port", tcp);
    __system_property_get("sys.usb.config", usb);
    char line[768];
    int count = snprintf(line, sizeof(line),
                         "CORE_HELPER_V168_GATE_TRIAL uid=%ld gid=%ld context=%s "
                         "restore=%d property_rc=%d context_rc=%d daemon_rc=%d "
                         "tcp_rc=%d tcp=%s usb_rc=%d usb=%s worker_rc=%d shell_bridge_rc=%d mic_worker_rc=%d button_worker_rc=%d gate_rc=%d "
                         "mnt_self=%s mnt_init=%s socket_ok=%d socket_errno=%d "
                         "argc=%d argv0=%s\n",
                         (long)getuid(), (long)getgid(), context,
                         restored, property_result, context_result, daemon_result,
                         tcp_result, tcp, usb_result, usb, worker_result, shell_bridge_result,
                         mic_worker_result, button_worker_result, gate_result,
                         self_mnt, init_mnt, socket_ok, socket_error,
                         argc, argc > 0 ? argv[0] : "none");
    if (count > 0 && (size_t)count < sizeof(line)) write(fd, line, (size_t)count);
    fsync(fd);
    close(fd);
}

static int serve(void) {
    struct stat directory;
    const char *files = "/data/data/org.local.lidar.binderprobe/files";
    if (stat(files, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid < APP_UID_MIN || directory.st_uid > APP_UID_MAX ||
        directory.st_gid != directory.st_uid) return 20;
    /* Android reassigns app UIDs after a factory reset. Bind this broker
     * only to the package's actual private files owner for this boot. */
    uid_t app_uid = directory.st_uid;
    struct stat old;
    if (lstat(SOCKET_PATH, &old) == 0) {
        if (!S_ISSOCK(old.st_mode)) return 21;
        if (unlink(SOCKET_PATH)) return 22;
    } else if (errno != ENOENT) return 23;

    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return 24;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (strlen(SOCKET_PATH) >= sizeof(addr.sun_path)) return 25;
    strcpy(addr.sun_path, SOCKET_PATH);
    mode_t previous = umask(077);
    int bound = bind(listener, (struct sockaddr *)&addr,
                     offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1);
    umask(previous);
    if (bound) return 26;
    if (chown(SOCKET_PATH, app_uid, app_uid) || chmod(SOCKET_PATH, 0600)) return 27;
    if (listen(listener, 1)) return 28;

    /* The broker accepts only fixed read-only diagnostics from the app UID.
     * It accepts no paths, arbitrary shell commands, or network connections. */
    time_t deadline = time(NULL) + 300;
    int accepted = 0;
    while (time(NULL) < deadline && accepted < 8) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);
        struct timeval wait = { .tv_sec = 1, .tv_usec = 0 };
        int ready = select(listener + 1, &readfds, NULL, NULL, &wait);
        if (ready <= 0) continue;
        int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) continue;
        struct timeval io_timeout = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                   &io_timeout, sizeof(io_timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
                   &io_timeout, sizeof(io_timeout));
        struct ucred peer;
        socklen_t size = sizeof(peer);
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 &&
            size == sizeof(peer) && peer.uid == app_uid) {
            char request[16] = {0};
            ssize_t count = read(client, request, sizeof(request) - 1);
            if (count == 5 && memcmp(request, "PING\n", 5) == 0) {
                char reply[128];
                int length = snprintf(reply, sizeof(reply),
                                      "ROOT_BRIDGE_V146 uid=%ld gid=%ld pid=%ld peer=%ld\n",
                                      (long)getuid(), (long)getgid(),
                                      (long)getpid(), (long)peer.uid);
                if (length > 0 && (size_t)length < sizeof(reply))
                    write(client, reply, (size_t)length);
                accepted++;
            } else if (count == 8 && memcmp(request, "EXEC_ID\n", 8) == 0) {
                int output[2];
                if (pipe2(output, O_CLOEXEC) == 0) {
                    pid_t child = fork();
                    if (child == 0) {
                        close(output[0]);
                        dup2(output[1], STDOUT_FILENO);
                        dup2(output[1], STDERR_FILENO);
                        close(output[1]);
                        execl("/system/bin/id", "id", (char *)NULL);
                        _exit(127);
                    }
                    close(output[1]);
                    char result[256] = {0};
                    ssize_t length = read(output[0], result, sizeof(result) - 1);
                    close(output[0]);
                    int status = -1;
                    if (child > 0) waitpid(child, &status, 0);
                    char reply[320];
                    int size = snprintf(reply, sizeof(reply),
                                        "EXEC_ID_V146 exit=%d output=%.*s",
                                        WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                                        length > 0 ? (int)length : 0, result);
                    if (size > 0 && (size_t)size < sizeof(reply))
                        write(client, reply, (size_t)size);
                    accepted++;
                }
            } else if (count == 5 && memcmp(request, "CAPS\n", 5) == 0) {
                int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
                if (fd >= 0) {
                    char status[4096] = {0};
                    ssize_t length = read(fd, status, sizeof(status) - 1);
                    close(fd);
                    if (length > 0) {
                        char *cap = strstr(status, "CapEff:");
                        if (cap) {
                            char reply[80];
                            int size = snprintf(reply, sizeof(reply),
                                                "CAPS_V146 %.*s",
                                                (int)strcspn(cap, "\n") + 1, cap);
                            if (size > 0 && (size_t)size < sizeof(reply))
                                write(client, reply, (size_t)size);
                            accepted++;
                        }
                    }
                }
            } else if (count == 11 && memcmp(request, "GATE_CHECK\n", 11) == 0) {
                int result = gate_check_filter();
                char reply[80];
                int length = snprintf(reply, sizeof(reply),
                                      "GATE_CHECK_V151 rc=%d checked=1\n", result);
                if (length > 0 && (size_t)length < sizeof(reply))
                    write(client, reply, (size_t)length);
                accepted++;
            } else if (count == 13 && memcmp(request, "GATE_PERSIST\n", 13) == 0) {
                int result = gate_persist_wifi_off();
                char reply[80];
                int length = snprintf(reply, sizeof(reply),
                                      "GATE_PERSIST_V151 rc=%d checked=1\n", result);
                if (length > 0 && (size_t)length < sizeof(reply))
                    write(client, reply, (size_t)length);
                accepted++;
            }
        }
        close(client);
    }
    close(listener);
    unlink(SOCKET_PATH);
    return 0;
}

/* Entered by the kernel's core-dump pipe after both image-specific writes.
 * Read main() in order: restore core_pattern; check UID 0 and publish proof;
 * enable the already-authorized local USB transport; start a bounded local
 * helper; then start optional, separately pinned workers. The voice, button
 * and network features are not part of the Binder primitive. SELinux stays
 * Permissive in the tested chain; see the release limits. */
int main(int argc, char **argv) {
    /* 1. Restore the short-lived pipe target before accepting commands. */
    int restore_fd = open("/proc/sys/kernel/core_pattern", O_WRONLY | O_CLOEXEC);
    int restored = 0;
    if (restore_fd >= 0) {
        restored = write(restore_fd, "core", 4) == 4;
        close(restore_fd);
    }
    /* With an armed policy, install the filter before any worker opens WiFi. */
    int gate_result = getuid() == 0 && restored ? gate_setup_after_root() : -EPERM;
    int property_result = stock_setprop("sys.lidar.root_probe", "v154");
    int context_result = getuid() == 0 && restored ? context_probe() : -1;

    /* 2. Start with the proven USB recovery path. The property worker can add
     * normal, authenticated TCP ADB after its key/config preflight. */
    int tcp_result = -1;
    int usb_result = -1;
    if (getuid() == 0 && restored && property_result == 0) {
        tcp_result = stock_setprop("service.adb.tcp.port", "-1");
        char tcp[64] = {0};
        __system_property_get("service.adb.tcp.port", tcp);
        if (tcp_result == 0 && strcmp(tcp, "-1") == 0)
            usb_result = stock_setprop("sys.usb.config", "mtp,adb");
    }

    /* 3. Keep the narrow local proof/recovery socket available after the
     * crashing child has exited. It checks peer credentials and budgets
     * requests; a normal ADB shell is not automatically a root shell. */
    int daemon_result = -1;
    if (getuid() == 0 && restored) {
        pid_t child = fork();
        if (child == 0) {
            if (setsid() < 0) _exit(31);
            pid_t grandchild = fork();
            if (grandchild < 0) _exit(32);
            if (grandchild > 0) _exit(0);
            for (int fd = 0; fd < 64; ++fd) close(fd);
            int null = open("/dev/null", O_RDWR);
            if (null >= 0) {
                dup2(null, 0); dup2(null, 1); dup2(null, 2);
                if (null > 2) close(null);
            }
            _exit(serve());
        }
        daemon_result = child < 0 ? -errno : 0;
    }
    /* 4. Optional workers are independently checked. Their failure must be
     * recorded separately from the core UID-0 and USB evidence. */
    int worker_result = -1;
    if (getuid() == 0 && restored)
        worker_result = start_property_worker();
    int shell_bridge_result = -1;
    if (getuid() == 0 && restored)
        shell_bridge_result = start_shell_bridge();
    int mic_worker_result = -1;
    if (getuid() == 0 && restored)
        mic_worker_result = start_mic_worker();
    int button_worker_result = -1;
    if (getuid() == 0 && restored)
        button_worker_result = start_button_worker();
    int update_stop_rc = -1;
    int ahe_stop_rc = -1;
    int filed_stop_rc = -1;
    if (amazon_lockdown_enabled() && getuid() == 0 && restored) {
        update_stop_rc = stop_stock_service("update_engine");
        ahe_stop_rc = stop_stock_service("ahe");
        filed_stop_rc = stop_stock_service("amazonfiled");
    }
    write_amazon_stop_log(update_stop_rc, ahe_stop_rc, filed_stop_rc);
    write_marker(restored, property_result, context_result, daemon_result,
                 tcp_result, usb_result, worker_result, shell_bridge_result,
                 mic_worker_result, button_worker_result, gate_result,
                 argc, argv);
    return restored && property_result == 0 && daemon_result == 0 &&
           tcp_result == 0 && usb_result == 0 && worker_result == 0 &&
           shell_bridge_result == 0 ? 0 : 1;
}
