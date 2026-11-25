#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#ifndef POLICY_SIZE
#define POLICY_SIZE 363124
#endif
static unsigned char policy[POLICY_SIZE];

int main(void) {
    int source = open("/system_root/sepolicy", O_RDONLY | O_CLOEXEC);
    if (source < 0) {
        printf("POLICY_LOAD_FAIL source_errno=%d\n", errno);
        return 2;
    }
    size_t size = 0;
    while (size < POLICY_SIZE) {
        ssize_t count = read(source, policy + size, POLICY_SIZE - size);
        if (count <= 0) {
            printf("POLICY_LOAD_FAIL read_count=%zd errno=%d\n", count, errno);
            close(source);
            return 3;
        }
        size += (size_t)count;
    }
    unsigned char extra;
    if (read(source, &extra, 1) != 0) {
        puts("POLICY_LOAD_FAIL source_too_long");
        close(source);
        return 4;
    }
    close(source);

    int target = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
    if (target < 0) {
        printf("POLICY_LOAD_FAIL target_errno=%d\n", errno);
        return 5;
    }
    ssize_t written = write(target, policy, POLICY_SIZE);
    int saved_errno = errno;
    close(target);
    if (written != POLICY_SIZE) {
        printf("POLICY_LOAD_FAIL written=%zd errno=%d\n", written, saved_errno);
        return 6;
    }
    printf("POLICY_LOAD_SINGLE_WRITE_OK bytes=%d\n", POLICY_SIZE);
    return 0;
}
