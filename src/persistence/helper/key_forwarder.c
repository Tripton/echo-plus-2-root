// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <linux/input.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#define SOCKET_NAME "echo_plus2_buttons_v1"

static int send_key(char value) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    memcpy(addr.sun_path + 1, SOCKET_NAME, sizeof(SOCKET_NAME) - 1);
    socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                   sizeof(SOCKET_NAME));
    int result = connect(fd, (struct sockaddr *)&addr, length);
    if (result == 0) {
        result = write(fd, &value, 1) == 1 ? 0 : -1;
        shutdown(fd, SHUT_WR);
    }
    close(fd);
    return result;
}

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int open_named_input(const char *path, const char *name) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char actual[80] = {0};
    if (ioctl(fd, EVIOCGNAME(sizeof(actual)), actual) < 0 ||
        strcmp(actual, name) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--test-action") == 0)
        return send_key('A') == 0 ? 0 : 4;
    if (argc == 2 && strcmp(argv[1], "--test-microphone") == 0)
        return send_key('M') == 0 ? 0 : 4;
    int64_t seconds = 120;
    int forever = 0;
    if (argc == 2 && strcmp(argv[1], "--forever") == 0) {
        forever = 1;
    } else if (argc == 3 && strcmp(argv[1], "--seconds") == 0) {
        char *end = NULL;
        long value = strtol(argv[2], &end, 10);
        if (!end || *end || value < 1 || value > 3600) return 2;
        seconds = value;
    } else if (argc != 1) return 2;

    int action = open_named_input("/dev/input/event4", "gpio-keys");
    int mute = open_named_input("/dev/input/event1", "gpio-privacy");
    if (action < 0 || mute < 0) {
        fprintf(stderr, "KEY_FORWARDER_INPUT_UNAVAILABLE errno=%d\n", errno);
        if (action >= 0) close(action);
        if (mute >= 0) close(mute);
        return 3;
    }
    struct pollfd inputs[2] = {
        { .fd = action, .events = POLLIN },
        { .fd = mute, .events = POLLIN },
    };
    int64_t start = monotonic_ms();
    int64_t last_action = -1000, last_mute = -1000;
    if (forever) puts("KEY_FORWARDER_READY forever");
    else printf("KEY_FORWARDER_READY seconds=%lld\n", (long long)seconds);
    fflush(stdout);
    while (forever || monotonic_ms() - start < seconds * 1000) {
        int ready = poll(inputs, 2, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) break;
        for (int i = 0; i < 2; ++i) {
            if (inputs[i].revents & (POLLHUP | POLLERR | POLLNVAL)) goto done;
            if (!(inputs[i].revents & POLLIN)) continue;
            struct input_event ev;
            ssize_t count = read(inputs[i].fd, &ev, sizeof(ev));
            if (count != sizeof(ev)) goto done;
            if (ev.type != EV_KEY) continue;
            if ((i == 0 && ev.code == KEY_HELP) ||
                (i == 1 && ev.code == KEY_MUTE)) {
                printf("KEY_FORWARDER_RAW input=%d code=%u value=%d\n",
                       i, ev.code, ev.value);
                fflush(stdout);
            }
            if (ev.value != 0) continue;
            int64_t now = monotonic_ms();
            if (i == 0 && ev.code == KEY_HELP && now - last_action >= 250) {
                last_action = now;
                printf("KEY_FORWARDER_ACTION result=%d\n", send_key('A'));
                fflush(stdout);
            } else if (i == 1 && ev.code == KEY_MUTE && now - last_mute >= 250) {
                last_mute = now;
                printf("KEY_FORWARDER_MICROPHONE result=%d\n", send_key('M'));
                fflush(stdout);
            }
        }
    }
done:
    close(action);
    close(mute);
    puts("KEY_FORWARDER_STOPPED");
    return 0;
}
