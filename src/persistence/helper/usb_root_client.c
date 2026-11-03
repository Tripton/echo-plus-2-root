#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/data/local/tmp/lidar-root-v154.sock"

int main(int argc, char **argv) {
    if (argc != 2 || !argv[1][0] || strlen(argv[1]) > 1000 ||
        strchr(argv[1], '\n')) {
        fputs("usage: lidar-root-client 'one shell command'\n", stderr);
        return 2;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 3; }
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strcpy(addr.sun_path, SOCKET_PATH);
    if (connect(fd, (struct sockaddr *)&addr,
                offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1)) {
        perror("connect");
        close(fd);
        return 4;
    }
    char request[1024];
    int size = snprintf(request, sizeof(request), "RUN %s\n", argv[1]);
    if (size < 0 || size >= (int)sizeof(request) ||
        write(fd, request, (size_t)size) != size) {
        perror("write");
        close(fd);
        return 5;
    }
    shutdown(fd, SHUT_WR);
    char output[4096];
    ssize_t n;
    while ((n = read(fd, output, sizeof(output))) > 0) {
        if (write(STDOUT_FILENO, output, (size_t)n) != n) {
            perror("stdout");
            close(fd);
            return 6;
        }
    }
    if (n < 0) { perror("read"); close(fd); return 7; }
    close(fd);
    return 0;
}
